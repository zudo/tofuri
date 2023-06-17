pub const PREFIX_ADDRESS: &str = "0x";
pub const PREFIX_SECRET_KEY: &str = "SECRETx";
pub const BLOCK_SIZE_LIMIT: usize = 57797;
pub const MAX_TRANSMIT_SIZE: usize = 100_000;
pub const PROTOCOL_VERSION: &str = "tofuri/1.0.0";
pub const PROTOCOL_NAME: &str = "/sync/1";
pub const DECIMAL_PLACES: usize = 18;
pub const COIN: u128 = 10_u128.pow(DECIMAL_PLACES as u32);
pub const BLOCK_TIME: u32 = 60;
pub const ELAPSED: u32 = 90;
pub const EXTENSION: &str = "tofuri";
pub const AMOUNT_BYTES: usize = 4;
pub const GENESIS_BLOCK_BETA: [u8; 32] = [0; 32];
pub const GENESIS_BLOCK_PREVIOUS_HASH: [u8; 32] = [0; 32];
pub const GENESIS_BLOCK_TIMESTAMP: u32 = 1680000000;
pub const GENESIS_BLOCK_HASH: [u8; 32] = [
    0x5c, 0x85, 0xa0, 0x30, 0x4e, 0x26, 0x58, 0xbb, 0x8d, 0xa9, 0x0b, 0xf3, 0xb3, 0xcf, 0xfa, 0x50,
    0x59, 0x08, 0xdb, 0xf7, 0xfa, 0xe8, 0x16, 0xd8, 0x48, 0xb7, 0x7b, 0xc4, 0xe5, 0x08, 0xca, 0x54,
];
pub const RECOVERY_ID: i32 = 0;
pub const P2P_RATELIMIT_REQUEST_TIMEOUT: u32 = 3600;
pub const P2P_RATELIMIT_RESPONSE_TIMEOUT: u32 = 3600;
pub const P2P_RATELIMIT_REQUEST: usize = 60 + 1;
pub const P2P_RATELIMIT_RESPONSE: usize = 60 + 1;
pub const P2P_RATELIMIT_GOSSIPSUB_MESSAGE_BLOCK: usize = 1 + 1;
pub const P2P_RATELIMIT_GOSSIPSUB_MESSAGE_TRANSACTION: usize = 60 * 100;
pub const P2P_RATELIMIT_GOSSIPSUB_MESSAGE_STAKE: usize = 60 * 100;
pub const P2P_RATELIMIT_GOSSIPSUB_MESSAGE_PEERS: usize = 1 + 1;
pub const SHARE_PEERS_MAX_LEN: usize = 100;
pub const MAINNET: u16 = 2020;
pub const TESTNET: u16 = 3030;
