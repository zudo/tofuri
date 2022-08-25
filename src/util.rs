use crate::types;
use ed25519_dalek::Keypair;
use merkle_cbt::{merkle_tree::Merge, CBMT as ExCBMT};
use rand::rngs::OsRng;
use std::{
    error::Error,
    fs::File,
    io::{BufRead, BufReader},
    path::Path,
    time::{SystemTime, UNIX_EPOCH},
};
pub fn keygen() -> Keypair {
    let mut csprng = OsRng {};
    Keypair::generate(&mut csprng)
}
pub struct Hasher;
impl Merge for Hasher {
    type Item = [u8; 32];
    fn merge(left: &Self::Item, right: &Self::Item) -> Self::Item {
        let mut hasher = blake3::Hasher::new();
        hasher.update(left);
        hasher.update(right);
        hasher.finalize().into()
    }
}
pub type CBMT = ExCBMT<[u8; 32], Hasher>;
pub fn timestamp() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("Time went backwards")
        .as_secs()
}
pub fn hash(input: &[u8]) -> types::Hash {
    blake3::hash(input).into()
}
pub fn read_lines(path: impl AsRef<Path>) -> Result<Vec<String>, Box<dyn Error>> {
    let file = File::open(path)?;
    let buf = BufReader::new(file);
    Ok(buf
        .lines()
        .map(|l| l.expect("Could not parse line"))
        .collect())
}
#[cfg(test)]
mod tests {
    use super::*;
    use ed25519::signature::{Signer, Verifier};
    use ed25519_dalek::{Keypair, PublicKey, SecretKey, Signature};
    use test::Bencher;
    #[test]
    fn test_hash() {
        assert_eq!(
            blake3::hash(b"test").to_string(),
            "4878ca0425c739fa427f7eda20fe845f6b2e46ba5fe2a14df5b1e32f50603215".to_string()
        );
    }
    #[bench]
    fn bench_hash(b: &mut Bencher) {
        b.iter(|| hash(b"test"));
    }
    #[bench]
    fn bench_ed25519_dalek_sign(b: &mut Bencher) {
        let keypair = keygen();
        let message: &[u8] = &[0; 32];
        b.iter(|| keypair.sign(message));
    }
    #[bench]
    fn bench_ed25519_dalek_verify(b: &mut Bencher) {
        let keypair = keygen();
        let message: &[u8] = &[0, 32];
        let signature: Signature = keypair.try_sign(message).unwrap();
        b.iter(|| keypair.public.verify(message, &signature));
    }
    #[bench]
    fn bench_ed25519_dalek_verify_strict(b: &mut Bencher) {
        let keypair = keygen();
        let message: &[u8] = &[0, 32];
        let signature: Signature = keypair.try_sign(message).unwrap();
        b.iter(|| keypair.public.verify_strict(message, &signature));
    }
    #[bench]
    fn bench_ed25519_dalek_keypair(b: &mut Bencher) {
        let keypair = keygen();
        let keypair_bytes = keypair.to_bytes();
        b.iter(|| Keypair::from_bytes(&keypair_bytes));
    }
    #[bench]
    fn bench_ed25519_dalek_secret_key(b: &mut Bencher) {
        let keypair = keygen();
        let secret_key_bytes = keypair.secret.to_bytes();
        b.iter(|| SecretKey::from_bytes(&secret_key_bytes));
    }
    #[bench]
    fn bench_ed25519_dalek_public_key(b: &mut Bencher) {
        let keypair = keygen();
        let public_key_bytes = keypair.public.to_bytes();
        b.iter(|| PublicKey::from_bytes(&public_key_bytes));
    }
    #[bench]
    fn bench_ed25519_dalek_signature(b: &mut Bencher) {
        let keypair = keygen();
        let message: &[u8] = &[0, 32];
        let signature: Signature = keypair.try_sign(message).unwrap();
        let signature_bytes = signature.to_bytes();
        b.iter(|| Signature::try_from(signature_bytes));
    }
}
