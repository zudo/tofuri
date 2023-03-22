use tofuri_address::address;
use tofuri_api_core::Block;
use tofuri_api_core::Stake;
use tofuri_api_core::Transaction;
use tofuri_block::BlockA;
use tofuri_stake::StakeA;
use tofuri_stake::StakeB;
use tofuri_transaction::TransactionA;
use tofuri_transaction::TransactionB;
#[derive(Debug)]
pub enum Error {
    Hex(hex::FromHexError),
    Address(tofuri_address::Error),
    Int(tofuri_int::Error),
    TryFromSliceError(core::array::TryFromSliceError),
}
pub fn block(block_a: &BlockA) -> Block {
    Block {
        hash: hex::encode(block_a.hash),
        previous_hash: hex::encode(block_a.previous_hash),
        timestamp: block_a.timestamp,
        beta: hex::encode(block_a.beta),
        pi: hex::encode(block_a.pi),
        forger_address: address::encode(&block_a.input_address()),
        signature: hex::encode(block_a.signature),
        transactions: block_a.transactions.iter().map(|x| hex::encode(x.hash)).collect(),
        stakes: block_a.stakes.iter().map(|x| hex::encode(x.hash)).collect(),
    }
}
pub fn transaction(transaction_a: &TransactionA) -> Transaction {
    Transaction {
        input_address: address::encode(&transaction_a.input_address),
        output_address: address::encode(&transaction_a.output_address),
        amount: tofuri_int::to_string(transaction_a.amount),
        fee: tofuri_int::to_string(transaction_a.fee),
        timestamp: transaction_a.timestamp,
        hash: hex::encode(transaction_a.hash),
        signature: hex::encode(transaction_a.signature),
    }
}
pub fn stake(stake_a: &StakeA) -> Stake {
    Stake {
        amount: tofuri_int::to_string(stake_a.amount),
        fee: tofuri_int::to_string(stake_a.fee),
        deposit: stake_a.deposit,
        timestamp: stake_a.timestamp,
        signature: hex::encode(stake_a.signature),
        input_address: address::encode(&stake_a.input_address),
        hash: hex::encode(stake_a.hash),
    }
}
pub fn transaction_b(transaction: &Transaction) -> Result<TransactionB, Error> {
    Ok(TransactionB {
        output_address: address::decode(&transaction.output_address).map_err(Error::Address)?,
        amount: tofuri_int::to_be_bytes(tofuri_int::from_str(&transaction.amount).map_err(Error::Int)?),
        fee: tofuri_int::to_be_bytes(tofuri_int::from_str(&transaction.fee).map_err(Error::Int)?),
        timestamp: transaction.timestamp,
        signature: hex::decode(&transaction.signature)
            .map_err(Error::Hex)?
            .as_slice()
            .try_into()
            .map_err(Error::TryFromSliceError)?,
    })
}
pub fn stake_b(stake: &Stake) -> Result<StakeB, Error> {
    Ok(StakeB {
        amount: tofuri_int::to_be_bytes(tofuri_int::from_str(&stake.amount).map_err(Error::Int)?),
        fee: tofuri_int::to_be_bytes(tofuri_int::from_str(&stake.fee).map_err(Error::Int)?),
        deposit: stake.deposit,
        timestamp: stake.timestamp,
        signature: hex::decode(&stake.signature)
            .map_err(Error::Hex)?
            .as_slice()
            .try_into()
            .map_err(Error::TryFromSliceError)?,
    })
}
