use std::collections::VecDeque;
pub type AxiomAmount = u64;
pub type Timestamp = u64;
pub type Height = usize;
pub type Heartbeats = usize;
pub type Checksum = [u8; 4];
pub type Nonce = [u8; 12];
pub type PublicKey = [u8; 32];
pub type SecretKey = [u8; 32];
pub type Salt = [u8; 32];
pub type Hash = [u8; 32];
pub type MerkleRoot = [u8; 32];
pub type Signature = [u8; 64];
pub type Hashes = Vec<Hash>;
pub type Staker = (PublicKey, Height);
pub type Stakers = VecDeque<Staker>;
pub type Ciphertext = Vec<u8>;
