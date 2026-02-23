// SPDX-License-Identifier: MIT
pragma solidity 0.8.34;

import {RootRegistry} from "./RootRegistry.sol";
import {TrustPathVerifier} from "./TrustPathVerifier.sol";

/**
 * @title TrustNetPaymentsGuardModule
 * @notice Minimal on-chain payments guard for TrustNet ALLOW-only enforcement.
 *
 * This contract is intentionally narrow for MVP:
 * - It guards ETH transfers held by this contract.
 * - A configured operator submits TrustNet proofs for (decider, target, context).
 * - Transfer executes only if proof verification yields ALLOW.
 * - Operational safeguards: epoch existence, root freshness, per-call deadline,
 *   replay protection, and max payment amount.
 */
contract TrustNetPaymentsGuardModule {
    RootRegistry private immutable ROOT_REGISTRY;

    address public owner;
    address public decider;

    bytes32 private immutable CONTEXT_ID;

    int8 private immutable ALLOW_THRESHOLD;
    int8 private immutable ASK_THRESHOLD;

    uint256 private immutable MAX_PAYMENT_AMOUNT_WEI;
    uint256 private immutable MAX_ROOT_AGE_SECONDS;

    mapping(bytes32 => bool) public usedOperationIds;

    error Unauthorized();
    error ZeroAddress();
    error InvalidContext();
    error InvalidThresholds(int8 allowThreshold, int8 askThreshold);
    error UnknownEpoch(uint256 epoch);
    error RootTooOld(uint256 epoch, uint256 rootTimestamp, uint256 maxAgeSeconds);
    error DeadlineExpired(uint256 deadline, uint256 nowTimestamp);
    error AmountExceedsPolicy(uint256 requested, uint256 maxAllowed);
    error OperationAlreadyUsed(bytes32 operationId);
    error DecisionAsk(int8 score);
    error DecisionDeny(int8 score);
    error EthTransferFailed();

    event OwnerTransferred(address indexed previousOwner, address indexed newOwner);
    event DeciderChanged(address indexed previousDecider, address indexed newDecider);
    event PaymentExecuted(
        bytes32 indexed operationId,
        uint256 indexed epoch,
        address indexed target,
        address to,
        uint256 amountWei,
        int8 score,
        address endorser,
        bytes32 graphRoot
    );

    struct PaymentRequest {
        uint256 epoch;
        uint256 deadline;
        bytes32 operationId;
        address target;
        address endorser;
        address payable to;
        uint256 amountWei;
        TrustPathVerifier.SmmProof proofDt;
        TrustPathVerifier.SmmProof proofDe;
        TrustPathVerifier.SmmProof proofEt;
    }

    modifier onlyOwner() {
        _onlyOwner();
        _;
    }

    function _onlyOwner() internal view {
        if (msg.sender != owner) {
            revert Unauthorized();
        }
    }

    constructor(
        address _rootRegistry,
        address _owner,
        address _decider,
        bytes32 _contextId,
        int8 _allowThreshold,
        int8 _askThreshold,
        uint256 _maxPaymentAmountWei,
        uint256 _maxRootAgeSeconds
    ) {
        if (_rootRegistry == address(0) || _owner == address(0) || _decider == address(0)) {
            revert ZeroAddress();
        }
        if (_contextId == bytes32(0)) {
            revert InvalidContext();
        }
        if (_askThreshold > _allowThreshold) {
            revert InvalidThresholds(_allowThreshold, _askThreshold);
        }

        ROOT_REGISTRY = RootRegistry(_rootRegistry);
        owner = _owner;
        decider = _decider;
        CONTEXT_ID = _contextId;

        ALLOW_THRESHOLD = _allowThreshold;
        ASK_THRESHOLD = _askThreshold;

        MAX_PAYMENT_AMOUNT_WEI = _maxPaymentAmountWei;
        MAX_ROOT_AGE_SECONDS = _maxRootAgeSeconds;
    }

    receive() external payable {}

    function rootRegistry() public view returns (RootRegistry) {
        return ROOT_REGISTRY;
    }

    function contextId() public view returns (bytes32) {
        return CONTEXT_ID;
    }

    function allowThreshold() public view returns (int8) {
        return ALLOW_THRESHOLD;
    }

    function askThreshold() public view returns (int8) {
        return ASK_THRESHOLD;
    }

    function maxPaymentAmountWei() public view returns (uint256) {
        return MAX_PAYMENT_AMOUNT_WEI;
    }

    function maxRootAgeSeconds() public view returns (uint256) {
        return MAX_ROOT_AGE_SECONDS;
    }

    function transferOwnership(address newOwner) external onlyOwner {
        if (newOwner == address(0)) {
            revert ZeroAddress();
        }

        address prevOwner = owner;
        owner = newOwner;
        emit OwnerTransferred(prevOwner, newOwner);
    }

    function setDecider(address newDecider) external onlyOwner {
        if (newDecider == address(0)) {
            revert ZeroAddress();
        }

        address prevDecider = decider;
        decider = newDecider;
        emit DeciderChanged(prevDecider, newDecider);
    }

    function executePayment(PaymentRequest calldata req) external onlyOwner {
        if (req.target == address(0) || req.to == address(0)) {
            revert ZeroAddress();
        }
        if (block.timestamp > req.deadline) {
            revert DeadlineExpired(req.deadline, block.timestamp);
        }
        if (req.amountWei > MAX_PAYMENT_AMOUNT_WEI) {
            revert AmountExceedsPolicy(req.amountWei, MAX_PAYMENT_AMOUNT_WEI);
        }
        if (usedOperationIds[req.operationId]) {
            revert OperationAlreadyUsed(req.operationId);
        }

        bytes32 graphRoot = ROOT_REGISTRY.getRootAt(req.epoch);
        if (graphRoot == bytes32(0)) {
            revert UnknownEpoch(req.epoch);
        }

        if (MAX_ROOT_AGE_SECONDS != 0) {
            uint256 rootTs = ROOT_REGISTRY.getEpochTimestamp(req.epoch);
            if (rootTs == 0 || block.timestamp > rootTs + MAX_ROOT_AGE_SECONDS) {
                revert RootTooOld(req.epoch, rootTs, MAX_ROOT_AGE_SECONDS);
            }
        }

        TrustPathVerifier.DecisionRequest memory decisionReq = TrustPathVerifier.DecisionRequest({
            graphRoot: graphRoot,
            contextId: CONTEXT_ID,
            decider: decider,
            target: req.target,
            endorser: req.endorser,
            proofDt: req.proofDt,
            proofDe: req.proofDe,
            proofEt: req.proofEt,
            allowThreshold: ALLOW_THRESHOLD,
            askThreshold: ASK_THRESHOLD
        });

        TrustPathVerifier.DecisionResult memory result = TrustPathVerifier.verifyAndDecide(decisionReq);

        if (result.decision == TrustPathVerifier.Decision.Ask) {
            revert DecisionAsk(result.score);
        }
        if (result.decision != TrustPathVerifier.Decision.Allow) {
            revert DecisionDeny(result.score);
        }

        // Mark operation before external call to prevent replay/reentrancy reuse.
        usedOperationIds[req.operationId] = true;

        (bool ok,) = req.to.call{value: req.amountWei}("");
        if (!ok) {
            revert EthTransferFailed();
        }

        emit PaymentExecuted(
            req.operationId,
            req.epoch,
            req.target,
            req.to,
            req.amountWei,
            result.score,
            req.endorser,
            graphRoot
        );
    }
}
