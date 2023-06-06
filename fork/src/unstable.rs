use crate::Error;
use crate::Fork;
use crate::Stable;
use rocksdb::DBWithThreadMode;
use rocksdb::SingleThreaded;
use serde::Deserialize;
use serde::Serialize;
use std::collections::HashMap;
use std::collections::VecDeque;
use tofuri_block::BlockA;
use tofuri_core::*;
use tofuri_stake::StakeA;
use tofuri_transaction::TransactionA;
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct Unstable {
    pub latest_block: BlockA,
    pub hashes: Vec<Hash>,
    pub stakers: VecDeque<AddressBytes>,
    latest_blocks: Vec<BlockA>,
    map_balance: HashMap<AddressBytes, u128>,
    map_staked: HashMap<AddressBytes, u128>,
}
impl Unstable {
    pub fn from(
        db: &DBWithThreadMode<SingleThreaded>,
        hashes: &[Hash],
        stable: &Stable,
    ) -> Unstable {
        let mut unstable = Unstable {
            hashes: vec![],
            stakers: stable.stakers.clone(),
            map_balance: stable.get_map_balance().clone(),
            map_staked: stable.get_map_staked().clone(),
            latest_block: BlockA::default(),
            latest_blocks: stable.get_latest_blocks().clone(),
        };
        crate::load(&mut unstable, db, hashes);
        unstable
    }
    pub fn check_overflow(
        &self,
        transactions: &Vec<TransactionA>,
        stakes: &Vec<StakeA>,
    ) -> Result<(), Error> {
        let mut map_balance: HashMap<AddressBytes, u128> = HashMap::new();
        let mut map_staked: HashMap<AddressBytes, u128> = HashMap::new();
        for transaction_a in transactions {
            let k = transaction_a.input_address;
            let mut balance = if map_balance.contains_key(&k) {
                *map_balance.get(&k).unwrap()
            } else {
                self.balance(&k)
            };
            balance = balance
                .checked_sub(transaction_a.amount + transaction_a.fee)
                .ok_or(Error::Overflow)?;
            map_balance.insert(k, balance);
        }
        for stake_a in stakes {
            let k = stake_a.input_address;
            let mut balance = if map_balance.contains_key(&k) {
                *map_balance.get(&k).unwrap()
            } else {
                self.balance(&k)
            };
            let mut staked = if map_staked.contains_key(&k) {
                *map_staked.get(&k).unwrap()
            } else {
                self.staked(&k)
            };
            if stake_a.deposit {
                balance = balance
                    .checked_sub(stake_a.amount + stake_a.fee)
                    .ok_or(Error::Overflow)?;
            } else {
                balance = balance.checked_sub(stake_a.fee).ok_or(Error::Overflow)?;
                staked = staked.checked_sub(stake_a.amount).ok_or(Error::Overflow)?;
            }
            map_balance.insert(k, balance);
            map_staked.insert(k, staked);
        }
        Ok(())
    }
    pub fn transaction_in_chain(&self, transaction_a: &TransactionA) -> bool {
        for block_a in self.latest_blocks.iter() {
            if block_a
                .transactions
                .iter()
                .any(|a| a.hash == transaction_a.hash)
            {
                return true;
            }
        }
        false
    }
    pub fn stake_in_chain(&self, stake_a: &StakeA) -> bool {
        for block_a in self.latest_blocks.iter() {
            if block_a.stakes.iter().any(|a| a.hash == stake_a.hash) {
                return true;
            }
        }
        false
    }
    pub fn balance(&self, address: &AddressBytes) -> u128 {
        crate::get_balance(self, address)
    }
    pub fn staked(&self, address: &AddressBytes) -> u128 {
        crate::get_staked(self, address)
    }
    pub fn next_staker(&self, timestamp: u32) -> Option<AddressBytes> {
        crate::next_staker(self, timestamp)
    }
    pub fn stakers_offline(&self, timestamp: u32, previous_timestamp: u32) -> Vec<AddressBytes> {
        crate::stakers_offline(self, timestamp, previous_timestamp)
    }
    pub fn stakers_n(&self, n: usize) -> Vec<AddressBytes> {
        crate::stakers_n(self, n).0
    }
}
impl Fork for Unstable {
    fn get_hashes_mut(&mut self) -> &mut Vec<Hash> {
        &mut self.hashes
    }
    fn get_stakers(&self) -> &VecDeque<AddressBytes> {
        &self.stakers
    }
    fn get_stakers_mut(&mut self) -> &mut VecDeque<AddressBytes> {
        &mut self.stakers
    }
    fn get_map_balance(&self) -> &HashMap<AddressBytes, u128> {
        &self.map_balance
    }
    fn get_map_balance_mut(&mut self) -> &mut HashMap<AddressBytes, u128> {
        &mut self.map_balance
    }
    fn get_map_staked(&self) -> &HashMap<AddressBytes, u128> {
        &self.map_staked
    }
    fn get_map_staked_mut(&mut self) -> &mut HashMap<AddressBytes, u128> {
        &mut self.map_staked
    }
    fn get_latest_block(&self) -> &BlockA {
        &self.latest_block
    }
    fn get_latest_block_mut(&mut self) -> &mut BlockA {
        &mut self.latest_block
    }
    fn get_latest_blocks(&self) -> &Vec<BlockA> {
        &self.latest_blocks
    }
    fn get_latest_blocks_mut(&mut self) -> &mut Vec<BlockA> {
        &mut self.latest_blocks
    }
    fn is_stable() -> bool {
        false
    }
    fn append_block(&mut self, block_a: &BlockA, previous_timestamp: u32, loading: bool) {
        crate::append_block(self, block_a, previous_timestamp, loading)
    }
}
