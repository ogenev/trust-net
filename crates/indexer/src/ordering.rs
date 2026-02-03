//! Ordering helpers for observed-at keys.

/// Encode chain ordering tuple (block, tx, log) into a u64.
///
/// This packs the tuple as:
/// - high 32 bits: block number (clamped to u32::MAX)
/// - next 16 bits: tx index (clamped to u16::MAX)
/// - low 16 bits: log index (clamped to u16::MAX)
///
/// This preserves lexicographic ordering as long as values stay within
/// the allocated bit widths. For MVP chains, this is sufficient.
pub fn observed_at_for_chain(block_number: u64, tx_index: u64, log_index: u64) -> u64 {
    let block = block_number.min(u64::from(u32::MAX));
    let tx = tx_index.min(u64::from(u16::MAX));
    let log = log_index.min(u64::from(u16::MAX));

    (block << 32) | (tx << 16) | log
}

/// Encode server ordering tuple (server sequence) into a u64.
pub fn observed_at_for_server(server_seq: u64) -> u64 {
    server_seq
}
