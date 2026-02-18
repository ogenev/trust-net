import {
  ASK_MODE_BLOCK,
  DECISION_ASK,
  DECISION_DENY,
  addReceiptMetadataToMessage,
  buildCallKey,
  buildDecisionBlockReason,
  emitActionReceipt,
  ensureDecisionConsistency,
  fetchDecision,
  fetchRoot,
  findToolMapping,
  loadToolMap,
  normalizeDecision,
  parseConfig,
  persistReceipt,
  queuePush,
  queueShift,
  resolveTargetPrincipalId,
  MODE_LOCAL_LITE,
  shouldVerifyDecisionBundleAnchored,
  verifyDecisionBundleAnchored,
} from "./src/internal.js";
import {
  ASK_ACTION_ALLOW_ALWAYS,
  ASK_ACTION_ALLOW_ONCE,
  ASK_ACTION_ALLOW_TTL,
  ASK_ACTION_BLOCK,
  buildAskActionEvidenceRef,
  buildAskPromptPayload,
  consumeAskTicket,
  defaultAskTtlSecondsForMapping,
  issueAskTicket,
  normalizeAskAction,
} from "./src/ask-actions.js";
import { decideLocalTrust } from "./src/decision-engine.js";
import { openTrustStore } from "./src/store.js";

const DIRECT_ALLOW_LEVEL = 2;
const DIRECT_BLOCK_LEVEL = -2;

function deriveThresholdsForMapping(mapping) {
  const riskTier =
    typeof mapping?.riskTier === "string" ? mapping.riskTier.trim().toLowerCase() : "";
  if (riskTier === "low") {
    return { allow: 1, ask: 1 };
  }
  return { allow: 2, ask: 1 };
}

function readAskActionInput(event, ctx) {
  if (event && typeof event === "object" && event.trustnetAskAction) {
    return event.trustnetAskAction;
  }
  if (ctx && typeof ctx === "object" && ctx.trustnetAskAction) {
    return ctx.trustnetAskAction;
  }
  return undefined;
}

function applyAskAction({
  askAction,
  mapping,
  targetPrincipalId,
  config,
  trustStore,
  callKey,
  sessionKey,
  toolName,
}) {
  const nowMs = Date.now();

  if (askAction.action === ASK_ACTION_ALLOW_ONCE) {
    return {
      allow: true,
      action: askAction.action,
      userApproved: true,
      persistedEdge: false,
    };
  }

  if (askAction.action === ASK_ACTION_ALLOW_ALWAYS) {
    trustStore.upsertEdgeLatest({
      rater: config.decider,
      target: targetPrincipalId,
      contextId: mapping.contextId,
      level: DIRECT_ALLOW_LEVEL,
      updatedAt: nowMs,
      source: "ask-action:allow-always",
      evidenceRef: buildAskActionEvidenceRef({
        action: askAction.action,
        callKey,
        sessionKey,
        toolName,
      }),
    });
    return {
      allow: true,
      action: askAction.action,
      userApproved: true,
      persistedEdge: true,
    };
  }

  if (askAction.action === ASK_ACTION_ALLOW_TTL) {
    const ttlSeconds = askAction.ttlSeconds ?? defaultAskTtlSecondsForMapping(mapping);
    const expiresAtMs = nowMs + ttlSeconds * 1000;
    trustStore.upsertEdgeLatest({
      rater: config.decider,
      target: targetPrincipalId,
      contextId: mapping.contextId,
      level: DIRECT_ALLOW_LEVEL,
      updatedAt: nowMs,
      source: "ask-action:allow-ttl",
      evidenceRef: buildAskActionEvidenceRef({
        action: askAction.action,
        ttlSeconds,
        expiresAtMs,
        callKey,
        sessionKey,
        toolName,
      }),
    });
    return {
      allow: true,
      action: askAction.action,
      ttlSeconds,
      expiresAtMs,
      userApproved: true,
      persistedEdge: true,
    };
  }

  if (askAction.action === ASK_ACTION_BLOCK) {
    trustStore.upsertEdgeLatest({
      rater: config.decider,
      target: targetPrincipalId,
      contextId: mapping.contextId,
      level: DIRECT_BLOCK_LEVEL,
      updatedAt: nowMs,
      source: "ask-action:block",
      evidenceRef: buildAskActionEvidenceRef({
        action: askAction.action,
        callKey,
        sessionKey,
        toolName,
      }),
    });
    return {
      allow: false,
      action: askAction.action,
      userApproved: false,
      persistedEdge: true,
    };
  }

  throw new Error(`unsupported TrustNet ASK action: ${askAction.action}`);
}

export default function registerTrustNetOpenClawPlugin(api) {
  let config;
  let toolMapEntries;
  let trustStore;
  try {
    config = parseConfig(api);
    toolMapEntries = loadToolMap(config.toolMapPath);
    trustStore = openTrustStore(config.trustStorePath);
    trustStore.upsertAgent({
      principalId: config.decider,
      source: "plugin-config",
      metadata: {
        role: "decider",
      },
    });
  } catch (error) {
    const reason = error instanceof Error ? error.message : String(error);
    api.logger.warn?.(
      `trustnet-openclaw: plugin is inactive until valid config is provided (${reason})`,
    );
    return;
  }

  const pendingByCallKey = new Map();
  const pendingAskByTicket = new Map();
  const receiptSummariesBySessionTool = new Map();

  api.logger.debug?.(
    `trustnet-openclaw: loaded ${toolMapEntries.length} tool mapping entries from ${config.toolMapPath}`,
  );
  api.logger.debug?.(`trustnet-openclaw: local trust store ready at ${config.trustStorePath}`);

  api.on("before_tool_call", async (event, ctx) => {
    try {
      const mapping = findToolMapping(toolMapEntries, event.toolName);
      if (!mapping) {
        if (config.unmappedDecision === DECISION_DENY) {
          return {
            block: true,
            blockReason: `TrustNet DENY: no tool mapping for '${event.toolName}'`,
          };
        }
        return {
          block: true,
          blockReason: `TrustNet ASK: no tool mapping for '${event.toolName}'`,
        };
      }

      const targetPrincipalId = resolveTargetPrincipalId(config, ctx);
      const callKey = buildCallKey(ctx.sessionKey, event.toolName, event.params);
      trustStore.upsertAgent({
        principalId: targetPrincipalId,
        source: "runtime-session",
        metadata: {
          sessionKey: ctx.sessionKey ?? null,
        },
      });
      let decision;
      let root;
      let decisionBundle;
      let localDecision;
      let askResolution;

      if (config.mode === MODE_LOCAL_LITE) {
        const directEdge = trustStore.getEdgeLatest({
          rater: config.decider,
          target: targetPrincipalId,
          contextId: mapping.contextId,
        });
        const candidates = trustStore.listEndorserCandidates({
          decider: config.decider,
          target: targetPrincipalId,
          contextId: mapping.contextId,
        });
        localDecision = decideLocalTrust({
          thresholds: deriveThresholdsForMapping(mapping),
          levelDt: directEdge?.level ?? 0,
          candidates: candidates.map((candidate) => ({
            endorser: candidate.endorser,
            levelDe: candidate.levelDe,
            levelEt: candidate.levelEt,
          })),
        });
        decision = normalizeDecision(localDecision.decision);
      } else {
        [root, decisionBundle] = await Promise.all([
          fetchRoot(config),
          fetchDecision(config, targetPrincipalId, mapping.contextId),
        ]);

        ensureDecisionConsistency({
          mapping,
          decisionBundle,
          root,
          decider: config.decider,
          target: targetPrincipalId,
        });
        if (shouldVerifyDecisionBundleAnchored(config)) {
          verifyDecisionBundleAnchored(config, root, decisionBundle);
        }
        decision = normalizeDecision(decisionBundle.decision);
      }
      if (decision === DECISION_DENY) {
        return { block: true, blockReason: buildDecisionBlockReason(decision, mapping) };
      }
      if (decision === DECISION_ASK) {
        const askActionInput = readAskActionInput(event, ctx);
        if (askActionInput !== undefined) {
          const askAction = normalizeAskAction(askActionInput);
          const askTicket = consumeAskTicket(pendingAskByTicket, askAction.ticket);
          if (!askTicket) {
            throw new Error("invalid or expired TrustNet ASK ticket");
          }
          if (
            askTicket.callKey !== callKey ||
            askTicket.contextId !== mapping.contextId ||
            askTicket.targetPrincipalId !== targetPrincipalId
          ) {
            throw new Error("TrustNet ASK ticket does not match current tool call");
          }

          askResolution = applyAskAction({
            askAction,
            mapping,
            targetPrincipalId,
            config,
            trustStore,
            callKey,
            sessionKey: ctx.sessionKey,
            toolName: event.toolName,
          });
          if (!askResolution.allow) {
            return { block: true, blockReason: buildDecisionBlockReason(DECISION_DENY, mapping) };
          }
        } else if (config.askMode === ASK_MODE_BLOCK) {
          const askTicket = issueAskTicket(pendingAskByTicket, {
            callKey,
            contextId: mapping.contextId,
            targetPrincipalId,
          });
          return {
            block: true,
            blockReason: buildDecisionBlockReason(decision, mapping),
            trustnetAsk: buildAskPromptPayload({
              ticket: askTicket,
              mapping,
              targetPrincipalId,
            }),
          };
        }
      }

      queuePush(pendingByCallKey, callKey, {
        decision,
        mapping,
        root,
        decisionBundle,
        localDecision,
        askResolution,
        targetPrincipalId,
      });

      return undefined;
    } catch (error) {
      const reason = error instanceof Error ? error.message : String(error);
      api.logger.error?.(`trustnet-openclaw before_tool_call failed: ${reason}`);
      if (config.failOpen) {
        api.logger.warn?.("trustnet-openclaw failOpen=true, allowing tool execution");
        return undefined;
      }
      return {
        block: true,
        blockReason: `TrustNet enforcement error: ${reason}`,
      };
    }
  });

  api.on("after_tool_call", async (event, ctx) => {
    const callKey = buildCallKey(ctx.sessionKey, event.toolName, event.params);
    const pending = queueShift(pendingByCallKey, callKey);
    if (!pending) {
      return;
    }

    try {
      let receipt;
      if (pending.root && pending.decisionBundle) {
        receipt = emitActionReceipt(config, {
          toolName: event.toolName,
          params: event.params,
          result: event.result,
          error: event.error,
          root: pending.root,
          decisionBundle: pending.decisionBundle,
        });
      } else {
        receipt = {
          type: "trustnet.localReceipt.pending-v0.7",
          decision: pending.decision,
          score: pending.localDecision?.score ?? null,
          thresholds: pending.localDecision?.thresholds ?? null,
          endorser: pending.localDecision?.endorser ?? null,
          levels: {
            dt: pending.localDecision?.levelDt ?? 0,
            de: pending.localDecision?.levelDe ?? 0,
            et: pending.localDecision?.levelEt ?? 0,
          },
          askAction: pending.askResolution
            ? {
                action: pending.askResolution.action,
                ttlSeconds: pending.askResolution.ttlSeconds ?? null,
                expiresAtU64: pending.askResolution.expiresAtMs ?? null,
                persistedEdge: pending.askResolution.persistedEdge,
                userApproved: pending.askResolution.userApproved,
              }
            : null,
        };
      }
      const epoch =
        pending.decisionBundle && pending.decisionBundle.epoch !== undefined
          ? Number(pending.decisionBundle.epoch)
          : null;

      const meta = {
        generatedAt: new Date().toISOString(),
        callKey,
        toolName: event.toolName,
        decision: pending.decision,
        contextId: pending.mapping.contextId,
        epoch,
        receipt,
      };
      const receiptPath = persistReceipt(config, meta);
      trustStore.insertReceipt({
        callKey,
        sessionKey: ctx.sessionKey,
        decider: config.decider,
        target: pending.targetPrincipalId,
        toolName: event.toolName,
        contextId: pending.mapping.contextId,
        decision: pending.decision,
        epoch,
        createdAt: Date.now(),
        receiptId:
          typeof receipt?.receiptId === "string" && receipt.receiptId.length > 0
            ? receipt.receiptId
            : undefined,
        receipt,
      });
      queuePush(
        receiptSummariesBySessionTool,
        `${ctx.sessionKey ?? "no-session"}:${event.toolName}`,
        {
          decision: pending.decision,
          contextId: pending.mapping.contextId,
          epoch,
          receiptPath,
        },
      );

      api.logger.info?.(
        `trustnet-openclaw: receipt emitted for ${event.toolName}` +
          (receiptPath ? ` at ${receiptPath}` : ""),
      );
    } catch (error) {
      const reason = error instanceof Error ? error.message : String(error);
      api.logger.error?.(`trustnet-openclaw after_tool_call failed: ${reason}`);
    }
  });

  api.on("tool_result_persist", (event, ctx) => {
    const toolName = typeof event.toolName === "string" ? event.toolName : ctx.toolName;
    if (!toolName) {
      return;
    }
    const summary = queueShift(
      receiptSummariesBySessionTool,
      `${ctx.sessionKey ?? "no-session"}:${toolName}`,
    );
    if (!summary) {
      return;
    }

    const message = addReceiptMetadataToMessage(event.message, summary);
    if (!message) {
      return;
    }
    return { message };
  });

  api.on("shutdown", () => {
    try {
      trustStore.close();
    } catch (error) {
      const reason = error instanceof Error ? error.message : String(error);
      api.logger.error?.(`trustnet-openclaw failed to close trust store: ${reason}`);
    }
  });
}
