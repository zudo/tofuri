use crate::types;
pub const BLOCK_TRANSACTIONS_LIMIT: usize = BLOCK_TIME_MIN * 100;
pub const BLOCK_STAKES_LIMIT: usize = BLOCK_TIME_MIN;
pub const PENDING_TRANSACTIONS_LIMIT: usize = BLOCK_TRANSACTIONS_LIMIT;
pub const PENDING_STAKES_LIMIT: usize = BLOCK_STAKES_LIMIT;
pub const PREFIX_ADDRESS: &str = "0x";
pub const PREFIX_ADDRESS_KEY: &str = "Key0x";
pub const PROTOCOL_VERSION: &str = "experimental/1.0.0";
pub const SYNC_HISTORY_LENGTH: usize = 10;
pub const SYNC_BLOCKS: usize = 1;
pub const DECIMAL_PRECISION: types::Amount = 10u128.pow(18);
pub const MIN_STAKE: types::Amount = 0xde0b6b000000000;
pub const MIN_STAKE_MULTIPLIER: types::Amount = 64;
pub const MAX_STAKE: types::Amount = MIN_STAKE * MIN_STAKE_MULTIPLIER;
pub const BLOCK_TIME_MIN: usize = 2;
pub const BLOCK_TIME_MAX: usize = 4;
pub const EXTENSION: &str = "pea";
pub const AMOUNT_BYTES: usize = 4;
pub const PENDING_BLOCKS_LIMIT: usize = 10;
pub const TRUST_FORK_AFTER_BLOCKS: usize = 100;
