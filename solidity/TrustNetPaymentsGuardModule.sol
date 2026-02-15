// SPDX-License-Identifier: MIT
pragma solidity ^0.8.26;

import "./RootRegistry.sol";
import "./TrustPathVerifier.sol";

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
    RootRegistry public immutable rootRegistry;

    address public owner;
    address public decider;

    bytes32 public immutable contextId;

    int8 public immutable allowThreshold;
    int8 public immutable askThreshold;

    bool public immutable requirePositiveEtEvidence;
    bool public immutable requirePositiveDtEvidence;

    uint256 public immutable maxPaymentAmountWei;
    uint256 public immutable maxRootAgeSeconds;

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
        TrustPathVerifier.SmmProof proofDT;
        TrustPathVerifier.SmmProof proofDE;
        TrustPathVerifier.SmmProof proofET;
    }

    modifier onlyOwner() {
        if (msg.sender != owner) {
            revert Unauthorized();
        }
        _;
    }

    constructor(
        address _rootRegistry,
        address _owner,
        address _decider,
        bytes32 _contextId,
        int8 _allowThreshold,
        int8 _askThreshold,
        bool _requirePositiveEtEvidence,
        bool _requirePositiveDtEvidence,
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

        rootRegistry = RootRegistry(_rootRegistry);
        owner = _owner;
        decider = _decider;
        contextId = _contextId;

        allowThreshold = _allowThreshold;
        askThreshold = _askThreshold;

        requirePositiveEtEvidence = _requirePositiveEtEvidence;
        requirePositiveDtEvidence = _requirePositiveDtEvidence;

        maxPaymentAmountWei = _maxPaymentAmountWei;
        maxRootAgeSeconds = _maxRootAgeSeconds;
    }

    receive() external payable {}

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
        if (req.amountWei > maxPaymentAmountWei) {
            revert AmountExceedsPolicy(req.amountWei, maxPaymentAmountWei);
        }
        if (usedOperationIds[req.operationId]) {
            revert OperationAlreadyUsed(req.operationId);
        }

        bytes32 graphRoot = rootRegistry.getRootAt(req.epoch);
        if (graphRoot == bytes32(0)) {
            revert UnknownEpoch(req.epoch);
        }

        if (maxRootAgeSeconds != 0) {
            uint256 rootTs = rootRegistry.getEpochTimestamp(req.epoch);
            if (rootTs == 0 || block.timestamp > rootTs + maxRootAgeSeconds) {
                revert RootTooOld(req.epoch, rootTs, maxRootAgeSeconds);
            }
        }

        TrustPathVerifier.DecisionRequest memory decisionReq = TrustPathVerifier.DecisionRequest({
            graphRoot: graphRoot,
            contextId: contextId,
            decider: decider,
            target: req.target,
            endorser: req.endorser,
            proofDT: req.proofDT,
            proofDE: req.proofDE,
            proofET: req.proofET,
            allowThreshold: allowThreshold,
            askThreshold: askThreshold,
            requirePositiveEtEvidence: requirePositiveEtEvidence,
            requirePositiveDtEvidence: requirePositiveDtEvidence
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
