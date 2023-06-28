use key::Error;
use key::Key;
use serde::Deserialize;
use serde::Serialize;
use serde_big_array::BigArray;
use sha2::Digest;
use sha2::Sha256;
use vint::Vint;
#[derive(Clone, Debug, Eq, PartialEq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct Input {
    pub output: ([u8; 32], u8),
    #[serde(with = "BigArray")]
    pub signature: [u8; 64],
}
impl Input {
    pub fn hash(&self) -> [u8; 32] {
        let mut hasher = Sha256::new();
        hasher.update(&self.output.0);
        hasher.update(&self.output.1.to_be_bytes());
        hasher.finalize().into()
    }
}
#[derive(Clone, Debug, Eq, PartialEq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct Output {
    pub address: [u8; 20],
    pub value: Vint<4>,
}
impl Output {
    pub fn hash(&self) -> [u8; 32] {
        let mut hasher = Sha256::new();
        hasher.update(&self.address);
        hasher.update(self.value.0);
        hasher.finalize().into()
    }
}
#[derive(Clone, Debug, Eq, PartialEq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct Transaction {
    pub inputs: Vec<Input>,
    pub outputs: Vec<Output>,
}
impl Transaction {
    pub fn sign(mut inputs: Vec<(Input, Key)>, outputs: Vec<Output>) -> Result<Transaction, Error> {
        let mut transaction = Transaction {
            inputs: inputs.iter().map(|x| x.0.clone()).collect::<Vec<_>>(),
            outputs,
        };
        let hash = transaction.hash();
        for (input, key) in &mut inputs {
            input.signature = key.sign(&hash)?;
        }
        transaction.inputs = inputs.into_iter().map(|x| x.0).collect::<Vec<_>>();
        Ok(transaction)
    }
    pub fn hash(&self) -> [u8; 32] {
        let mut hasher = Sha256::new();
        for input in &self.inputs {
            hasher.update(&input.hash());
        }
        for output in &self.outputs {
            hasher.update(&output.hash());
        }
        hasher.finalize().into()
    }
}
