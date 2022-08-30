use crate::{db, types, util};
use ed25519::signature::Signer;
use rocksdb::{DBWithThreadMode, SingleThreaded};
use serde::{Deserialize, Serialize};
use serde_big_array::BigArray;
use std::error::Error;
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct Transaction {
    pub input: types::PublicKeyBytes,
    pub output: types::PublicKeyBytes,
    pub amount: types::AxiomAmount,
    pub fee: types::AxiomAmount,
    pub timestamp: types::Timestamp,
    #[serde(with = "BigArray")]
    pub signature: types::SignatureBytes,
}
impl Transaction {
    pub fn new(
        output: types::PublicKeyBytes,
        amount: types::AxiomAmount,
        fee: types::AxiomAmount,
    ) -> Transaction {
        Transaction {
            input: [0; 32],
            output,
            amount,
            fee,
            timestamp: util::timestamp(),
            signature: [0; 64],
        }
    }
    pub fn hash(&self) -> types::Hash {
        util::hash(&bincode::serialize(&TransactionHeader::from(self)).unwrap())
    }
    pub fn sign(&mut self, keypair: &types::Keypair) {
        self.input = keypair.public.to_bytes();
        self.signature = keypair.sign(&self.hash()).to_bytes();
    }
    pub fn verify(&self) -> Result<(), Box<dyn Error>> {
        let public_key = types::PublicKey::from_bytes(&self.input)?;
        let signature = types::Signature::from_bytes(&self.signature)?;
        Ok(public_key.verify_strict(&self.hash(), &signature)?)
    }
    pub fn is_valid(&self) -> bool {
        // check if output is a valid ed25519 public key
        // strictly verify transaction signature
        types::PublicKey::from_bytes(&self.output).is_ok()
            && self.verify().is_ok()
            && self.timestamp <= util::timestamp()
            && self.input != self.output
            && self.amount != 0
    }
    pub fn put(&self, db: &DBWithThreadMode<SingleThreaded>) -> Result<(), Box<dyn Error>> {
        db.put_cf(
            db::cf_handle_transactions(db)?,
            self.hash(),
            bincode::serialize(self)?,
        )?;
        Ok(())
    }
    pub fn get(
        db: &DBWithThreadMode<SingleThreaded>,
        hash: &[u8],
    ) -> Result<Transaction, Box<dyn Error>> {
        Ok(bincode::deserialize(
            &db.get_cf(db::cf_handle_transactions(db)?, hash)?
                .ok_or("transaction not found")?,
        )?)
    }
}
#[derive(Serialize, Deserialize, Debug)]
pub struct TransactionHeader {
    pub input: types::PublicKeyBytes,
    pub output: types::PublicKeyBytes,
    pub amount: types::AxiomAmount,
    pub fee: types::AxiomAmount,
    pub timestamp: types::Timestamp,
}
impl TransactionHeader {
    pub fn from(transaction: &Transaction) -> TransactionHeader {
        TransactionHeader {
            input: transaction.input,
            output: transaction.output,
            amount: transaction.amount,
            fee: transaction.fee,
            timestamp: transaction.timestamp,
        }
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    use test::Bencher;
    #[bench]
    fn bench_hash(b: &mut Bencher) {
        let transaction = Transaction::new([0; 32], 0, 0);
        b.iter(|| transaction.hash());
    }
    #[bench]
    fn bench_bincode_serialize(b: &mut Bencher) {
        let keypair = util::keygen();
        let mut transaction = Transaction::new([0; 32], 0, 0);
        transaction.sign(&keypair);
        println!("{:?}", transaction);
        println!("{:?}", bincode::serialize(&transaction));
        println!("{:?}", bincode::serialize(&transaction).unwrap().len());
        b.iter(|| bincode::serialize(&transaction));
    }
    #[bench]
    fn bench_bincode_deserialize(b: &mut Bencher) {
        let keypair = util::keygen();
        let mut transaction = Transaction::new([0; 32], 0, 0);
        transaction.sign(&keypair);
        let bytes = bincode::serialize(&transaction).unwrap();
        b.iter(|| {
            let _: Transaction = bincode::deserialize(&bytes).unwrap();
        });
    }
}
