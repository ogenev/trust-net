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
  verifyDecisionBundleAnchored,
} from "./src/internal.js";

export default function registerTrustNetOpenClawPlugin(api) {
  let config;
  let toolMapEntries;
  try {
    config = parseConfig(api);
    toolMapEntries = loadToolMap(config.toolMapPath);
  } catch (error) {
    const reason = error instanceof Error ? error.message : String(error);
    api.logger.warn?.(
      `trustnet-openclaw: plugin is inactive until valid config is provided (${reason})`,
    );
    return;
  }

  const pendingByCallKey = new Map();
  const receiptSummariesBySessionTool = new Map();

  api.logger.debug?.(
    `trustnet-openclaw: loaded ${toolMapEntries.length} tool mapping entries from ${config.toolMapPath}`,
  );

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
      const [root, decisionBundle] = await Promise.all([
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
      verifyDecisionBundleAnchored(config, root, decisionBundle);

      const decision = normalizeDecision(decisionBundle.decision);
      if (decision === DECISION_DENY) {
        return { block: true, blockReason: buildDecisionBlockReason(decision, mapping) };
      }
      if (decision === DECISION_ASK && config.askMode === ASK_MODE_BLOCK) {
        return { block: true, blockReason: buildDecisionBlockReason(decision, mapping) };
      }

      const callKey = buildCallKey(ctx.sessionKey, event.toolName, event.params);
      queuePush(pendingByCallKey, callKey, {
        decision,
        mapping,
        root,
        decisionBundle,
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
      const receipt = emitActionReceipt(config, {
        toolName: event.toolName,
        params: event.params,
        result: event.result,
        error: event.error,
        root: pending.root,
        decisionBundle: pending.decisionBundle,
      });

      const meta = {
        generatedAt: new Date().toISOString(),
        callKey,
        toolName: event.toolName,
        decision: pending.decision,
        contextId: pending.mapping.contextId,
        epoch: Number(pending.decisionBundle.epoch),
        receipt,
      };
      const receiptPath = persistReceipt(config, meta);
      queuePush(
        receiptSummariesBySessionTool,
        `${ctx.sessionKey ?? "no-session"}:${event.toolName}`,
        {
          decision: pending.decision,
          contextId: pending.mapping.contextId,
          epoch: Number(pending.decisionBundle.epoch),
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
}
