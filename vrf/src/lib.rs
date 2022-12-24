use curve25519_dalek::constants::RISTRETTO_BASEPOINT_POINT;
use curve25519_dalek::ristretto::{CompressedRistretto, RistrettoPoint};
use curve25519_dalek::scalar::Scalar;
use pea_core::util;
use rand_core::OsRng;
use sha3::Sha3_512;
#[derive(Debug, PartialEq, Eq)]
pub struct Proof {
    gamma: [u8; 32],
    c: [u8; 32],
    s: [u8; 32],
}
impl Proof {
    pub fn to_bytes(&self) -> [u8; 96] {
        let mut bytes = [0; 96];
        for i in 0..32 {
            bytes[i] = self.gamma[i];
            bytes[32 + i] = self.c[i];
            bytes[64 + i] = self.s[i];
        }
        bytes
    }
    pub fn from_bytes(input: &[u8; 96]) -> Proof {
        let mut gamma = [0; 32];
        let mut c = [0; 32];
        let mut s = [0; 32];
        gamma.copy_from_slice(&input[0..32]);
        c.copy_from_slice(&input[32..64]);
        s.copy_from_slice(&input[64..96]);
        Proof { gamma, c, s }
    }
}
fn serialize_point(ristretto_point: RistrettoPoint) -> [u8; 32] {
    ristretto_point.compress().to_bytes()
}
pub fn prove(alpha: &[u8], secret_key: &Scalar) -> ([u8; 32], Proof) {
    let h = RistrettoPoint::hash_from_bytes::<Sha3_512>(alpha);
    let gamma = h * secret_key;
    let k: Scalar = Scalar::random(&mut OsRng);
    let c = util::hash(
        &[
            serialize_point(RISTRETTO_BASEPOINT_POINT),
            serialize_point(h),
            serialize_point(RISTRETTO_BASEPOINT_POINT * secret_key),
            serialize_point(gamma),
            serialize_point(RISTRETTO_BASEPOINT_POINT * k),
            serialize_point(h * k),
        ]
        .concat(),
    );
    let c_scalar = Scalar::from_bytes_mod_order(c);
    let s = k - c_scalar * secret_key;
    let beta = util::hash(&serialize_point(gamma));
    (
        beta,
        Proof {
            gamma: gamma.compress().to_bytes(),
            c,
            s: s.to_bytes(),
        },
    )
}
pub fn verify(alpha: &[u8], public_key: &RistrettoPoint, beta: [u8; 32], pi: &Proof) -> bool {
    let gamma = CompressedRistretto::from_slice(&pi.gamma).decompress();
    if gamma.is_none() {
        return false;
    }
    let gamma = gamma.unwrap();
    let s = Scalar::from_canonical_bytes(pi.s);
    if s.is_none() {
        return false;
    }
    let s = s.unwrap();
    let c_scalar = Scalar::from_bytes_mod_order(pi.c);
    let u = public_key * c_scalar + RISTRETTO_BASEPOINT_POINT * s;
    let h = RistrettoPoint::hash_from_bytes::<Sha3_512>(alpha);
    let v = gamma * c_scalar + h * s;
    beta == util::hash(&serialize_point(gamma))
        && util::hash(
            &[
                serialize_point(RISTRETTO_BASEPOINT_POINT),
                serialize_point(h),
                serialize_point(*public_key),
                serialize_point(gamma),
                serialize_point(u),
                serialize_point(v),
            ]
            .concat(),
        ) == pi.c
}
#[cfg(test)]
mod tests {
    use super::*;
    use pea_key::Key;
    #[test]
    fn test_proof() {
        let key = Key::generate();
        let alpha = [];
        let (beta, pi) = prove(&alpha, &key.scalar);
        assert!(verify(&alpha, &key.ristretto_point(), beta, &pi));
    }
    #[test]
    fn test_fake_proof() {
        let key = Key::generate();
        let f_key = Key::generate();
        let alpha = [0];
        let f_alpha = [1];
        let (beta, pi) = prove(&alpha, &key.scalar);
        let (f_beta_0, f_pi) = prove(&alpha, &f_key.scalar);
        let mut f_beta_1 = beta.clone();
        f_beta_1[0] += 0x01;
        assert!(!verify(&f_alpha, &key.ristretto_point(), beta, &pi));
        assert!(!verify(&alpha, &f_key.ristretto_point(), beta, &pi));
        assert!(!verify(&alpha, &key.ristretto_point(), f_beta_0, &pi));
        assert!(!verify(&alpha, &key.ristretto_point(), f_beta_1, &pi));
        assert!(!verify(&alpha, &key.ristretto_point(), beta, &f_pi));
    }
    #[test]
    fn test_serialize() {
        let key = Key::generate();
        let alpha = [];
        let (_, pi) = prove(&alpha, &key.scalar);
        assert_eq!(pi, Proof::from_bytes(&pi.to_bytes()));
    }
}
