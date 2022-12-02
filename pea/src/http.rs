use crate::node::Node;
use colored::*;
use lazy_static::lazy_static;
use libp2p::gossipsub::TopicHash;
use log::{error, info};
use pea_address as address;
use pea_api::get;
use pea_db as db;
use pea_stake::Stake;
use pea_transaction::Transaction;
use regex::Regex;
use std::{error::Error, io::BufRead};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
lazy_static! {
    static ref GET: Regex = Regex::new(r"^GET [/_0-9A-Za-z]+ HTTP/1.1$").unwrap();
    static ref POST: Regex = Regex::new(r"^POST [/_0-9A-Za-z]+ HTTP/1.1$").unwrap();
    static ref INDEX: Regex = Regex::new(r" / ").unwrap();
    static ref INFO: Regex = Regex::new(r" /info ").unwrap();
    static ref SYNC: Regex = Regex::new(r" /sync ").unwrap();
    static ref DYNAMIC: Regex = Regex::new(r" /dynamic ").unwrap();
    static ref TRUSTED: Regex = Regex::new(r" /trusted ").unwrap();
    static ref OPTIONS: Regex = Regex::new(r" /options ").unwrap();
    static ref BALANCE: Regex = Regex::new(r" /balance/0[xX][0-9A-Fa-f]* ").unwrap();
    static ref BALANCE_STAKED: Regex = Regex::new(r" /balance_staked/0[xX][0-9A-Fa-f]* ").unwrap();
    static ref HEIGHT: Regex = Regex::new(r" /height ").unwrap();
    static ref HEIGHT_BY_HASH: Regex = Regex::new(r" /height/[0-9A-Fa-f]* ").unwrap();
    static ref BLOCK_LATEST: Regex = Regex::new(r" /block/latest ").unwrap();
    static ref HASH_BY_HEIGHT: Regex = Regex::new(r" /hash/[0-9]+ ").unwrap();
    static ref BLOCK_BY_HASH: Regex = Regex::new(r" /block/[0-9A-Fa-f]* ").unwrap();
    static ref TRANSACTION_BY_HASH: Regex = Regex::new(r" /transaction/[0-9A-Fa-f]* ").unwrap();
    static ref STAKE_BY_HASH: Regex = Regex::new(r" /stake/[0-9A-Fa-f]* ").unwrap();
    static ref TRANSACTION: Regex = Regex::new(r" /transaction ").unwrap();
    static ref TRANSACTION_SERIALIZED: usize = hex::encode(bincode::serialize(&Transaction::default()).unwrap()).len();
    static ref STAKE: Regex = Regex::new(r" /stake ").unwrap();
    static ref STAKE_SERIALIZED: usize = hex::encode(bincode::serialize(&Stake::default()).unwrap()).len();
    static ref PEERS: Regex = Regex::new(r" /peers ").unwrap();
}
pub async fn next(listener: &tokio::net::TcpListener) -> Result<tokio::net::TcpStream, Box<dyn Error>> {
    Ok(listener.accept().await?.0)
}
pub async fn handler(mut stream: tokio::net::TcpStream, node: &mut Node) -> Result<(), Box<dyn Error>> {
    let mut buffer = [0; 1024];
    let _ = stream.read(&mut buffer).await?;
    let first = buffer.lines().next().ok_or("http request first line")??;
    info!("{} {} {}", "API".cyan(), stream.peer_addr()?.to_string().magenta(), first);
    write(
        &mut stream,
        if GET.is_match(&first) {
            get(node, &first)
        } else if POST.is_match(&first) {
            post(node, &first, &buffer)
        } else {
            c405()
        }?,
    )
    .await?;
    stream.flush().await?;
    Ok(())
}
fn get(node: &mut Node, first: &str) -> Result<String, Box<dyn Error>> {
    if INDEX.is_match(first) {
        get_index()
    } else if INFO.is_match(first) {
        get_info(node)
    } else if SYNC.is_match(first) {
        get_sync(node)
    } else if DYNAMIC.is_match(first) {
        get_dynamic(node)
    } else if TRUSTED.is_match(first) {
        get_trusted(node)
    } else if OPTIONS.is_match(first) {
        get_options(node)
    } else if BALANCE.is_match(first) {
        get_balance(node, first)
    } else if BALANCE_STAKED.is_match(first) {
        get_staked_balance(node, first)
    } else if HEIGHT.is_match(first) {
        get_height(node)
    } else if HEIGHT_BY_HASH.is_match(first) {
        get_height_by_hash(node, first)
    } else if BLOCK_LATEST.is_match(first) {
        get_block_latest(node)
    } else if HASH_BY_HEIGHT.is_match(first) {
        get_hash_by_height(node, first)
    } else if BLOCK_BY_HASH.is_match(first) {
        get_block_by_hash(node, first)
    } else if TRANSACTION_BY_HASH.is_match(first) {
        get_transaction_by_hash(node, first)
    } else if STAKE_BY_HASH.is_match(first) {
        get_stake_by_hash(node, first)
    } else if PEERS.is_match(first) {
        get_peers(node)
    } else {
        c404()
    }
}
fn post(node: &mut Node, first: &str, buffer: &[u8; 1024]) -> Result<String, Box<dyn Error>> {
    if TRANSACTION.is_match(first) {
        post_transaction(node, buffer)
    } else if STAKE.is_match(first) {
        post_stake(node, buffer)
    } else {
        c404()
    }
}
async fn write(stream: &mut tokio::net::TcpStream, string: String) -> Result<(), Box<dyn Error>> {
    stream.write_all(string.as_bytes()).await?;
    Ok(())
}
fn json(string: String) -> String {
    format!(
        "\
HTTP/1.1 200 OK
Access-Control-Allow-Origin: *
Content-Type: application/json

{}",
        string
    )
}
fn text(string: String) -> String {
    format!(
        "\
HTTP/1.1 200 OK
Access-Control-Allow-Origin: *

{}",
        string
    )
}
fn get_index() -> Result<String, Box<dyn Error>> {
    Ok(text(format!(
        "\
{} = {{ version = \"{}\" }}
{}/tree/{}",
        env!("CARGO_PKG_NAME"),
        env!("CARGO_PKG_VERSION"),
        env!("CARGO_PKG_REPOSITORY"),
        env!("GIT_HASH"),
    )))
}
fn get_info(node: &mut Node) -> Result<String, Box<dyn Error>> {
    Ok(json(serde_json::to_string(&get::Data {
        public_key: node.blockchain.key.public(),
        tree_size: node.blockchain.tree.size(),
        heartbeats: node.heartbeats,
        lag: node.lag,
    })?))
}
fn get_sync(node: &mut Node) -> Result<String, Box<dyn Error>> {
    let last = node.last();
    let sync = node.sync();
    Ok(json(serde_json::to_string(&get::Sync {
        sync,
        last,
        height: node.blockchain.height(),
        bps: node.blockchain.sync.bps,
        downloading: node.blockchain.sync.downloading(),
        completed: node.blockchain.sync.completed,
        peers: node.swarm.behaviour().gossipsub.mesh_peers(&TopicHash::from_raw("blocks")).count(),
        index: node.blockchain.sync.index,
    })?))
}
fn get_dynamic(node: &mut Node) -> Result<String, Box<dyn Error>> {
    let dynamic = &node.blockchain.states.dynamic;
    Ok(json(serde_json::to_string(&get::State {
        balance: dynamic.balance(&node.blockchain.key.public_key_bytes()),
        balance_staked: dynamic.balance_staked(&node.blockchain.key.public_key_bytes()),
        hashes: dynamic.hashes.len(),
        latest_hashes: dynamic.hashes.iter().rev().take(16).map(hex::encode).collect(),
        stakers: dynamic.stakers.iter().map(address::public::encode).collect(),
    })?))
}
fn get_trusted(node: &mut Node) -> Result<String, Box<dyn Error>> {
    let trusted = &node.blockchain.states.trusted;
    Ok(json(serde_json::to_string(&get::State {
        balance: trusted.balance(&node.blockchain.key.public_key_bytes()),
        balance_staked: trusted.balance_staked(&node.blockchain.key.public_key_bytes()),
        hashes: trusted.hashes.len(),
        latest_hashes: trusted.hashes.iter().rev().take(16).map(hex::encode).collect(),
        stakers: trusted.stakers.iter().map(address::public::encode).collect(),
    })?))
}
fn get_options(node: &mut Node) -> Result<String, Box<dyn Error>> {
    Ok(json(serde_json::to_string(&get::Options {
        mint: node.mint,
        trust: node.blockchain.trust_fork_after_blocks,
        pending: node.blockchain.pending_blocks_limit,
        ban_offline: node.ban_offline,
        time_delta: node.blockchain.time_delta,
        max_established: node.max_established,
        tps: node.tps,
        bind_api: node.bind_api.clone(),
        host: node.host.clone(),
        tempdb: node.tempdb,
        tempkey: node.tempkey,
    })?))
}
fn get_balance(node: &mut Node, first: &str) -> Result<String, Box<dyn Error>> {
    let public_key = address::public::decode(BALANCE.find(first).ok_or("GET BALANCE 1")?.as_str().trim().get(9..).ok_or("GET BALANCE 2")?)?;
    let balance = node.blockchain.states.dynamic.balance(&public_key);
    Ok(json(serde_json::to_string(&balance)?))
}
fn get_staked_balance(node: &mut Node, first: &str) -> Result<String, Box<dyn Error>> {
    let public_key = address::public::decode(
        BALANCE_STAKED
            .find(first)
            .ok_or("GET BALANCE_STAKED 1")?
            .as_str()
            .trim()
            .get(16..)
            .ok_or("GET BALANCE_STAKED 2")?,
    )?;
    let balance = node.blockchain.states.dynamic.balance_staked(&public_key);
    Ok(json(serde_json::to_string(&balance)?))
}
fn get_height(node: &mut Node) -> Result<String, Box<dyn Error>> {
    let height = node.blockchain.height();
    Ok(json(serde_json::to_string(&height)?))
}
fn get_height_by_hash(node: &mut Node, first: &str) -> Result<String, Box<dyn Error>> {
    let hash = hex::decode(
        HEIGHT_BY_HASH
            .find(first)
            .ok_or("GET HEIGHT_BY_HASH 1")?
            .as_str()
            .trim()
            .get(8..)
            .ok_or("GET HEIGHT_BY_HASH 2")?,
    )?;
    let block = db::block::get(&node.blockchain.db, &hash)?;
    let height = node.blockchain.tree.height(&block.previous_hash);
    Ok(json(serde_json::to_string(&height)?))
}
fn get_block_latest(node: &mut Node) -> Result<String, Box<dyn Error>> {
    let block = &node.blockchain.states.dynamic.latest_block;
    Ok(json(serde_json::to_string(&get::Block {
        hash: hex::encode(block.hash()),
        previous_hash: hex::encode(block.previous_hash),
        timestamp: block.timestamp,
        public_key: address::public::encode(&block.public_key),
        signature: hex::encode(block.signature),
        transactions: block.transactions.iter().map(|x| hex::encode(x.hash())).collect(),
        stakes: block.stakes.iter().map(|x| hex::encode(x.hash())).collect(),
    })?))
}
fn get_hash_by_height(node: &mut Node, first: &str) -> Result<String, Box<dyn Error>> {
    let height = HASH_BY_HEIGHT
        .find(first)
        .ok_or("GET HASH_BY_HEIGHT 1")?
        .as_str()
        .trim()
        .get(6..)
        .ok_or("GET HASH_BY_HEIGHT 2")?
        .parse::<usize>()?;
    let states = &node.blockchain.states;
    let hashes_trusted = &states.trusted.hashes;
    let hashes_dynamic = &states.dynamic.hashes;
    if height >= hashes_trusted.len() + hashes_dynamic.len() {
        return Err("GET HASH_BY_HEIGHT 3".into());
    }
    let hash = if height < hashes_trusted.len() {
        hashes_trusted[height]
    } else {
        hashes_dynamic[height - hashes_trusted.len()]
    };
    Ok(json(serde_json::to_string(&hex::encode(hash))?))
}
fn get_block_by_hash(node: &mut Node, first: &str) -> Result<String, Box<dyn Error>> {
    let hash = hex::decode(
        BLOCK_BY_HASH
            .find(first)
            .ok_or("GET BLOCK_BY_HASH 1")?
            .as_str()
            .trim()
            .get(7..)
            .ok_or("GET BLOCK_BY_HASH 2")?,
    )?;
    let block = db::block::get(&node.blockchain.db, &hash)?;
    Ok(json(serde_json::to_string(&get::Block {
        hash: hex::encode(block.hash()),
        previous_hash: hex::encode(block.previous_hash),
        timestamp: block.timestamp,
        public_key: address::public::encode(&block.public_key),
        signature: hex::encode(block.signature),
        transactions: block.transactions.iter().map(|x| hex::encode(x.hash())).collect(),
        stakes: block.stakes.iter().map(|x| hex::encode(x.hash())).collect(),
    })?))
}
fn get_transaction_by_hash(node: &mut Node, first: &str) -> Result<String, Box<dyn Error>> {
    let hash = hex::decode(
        TRANSACTION_BY_HASH
            .find(first)
            .ok_or("GET TRANSACTION_BY_HASH 1")?
            .as_str()
            .trim()
            .get(13..)
            .ok_or("GET TRANSACTION_BY_HASH 2")?,
    )?;
    let transaction = db::transaction::get(&node.blockchain.db, &hash)?;
    Ok(json(serde_json::to_string(&get::Transaction {
        hash: hex::encode(transaction.hash()),
        public_key_input: address::public::encode(&transaction.public_key_input),
        public_key_output: address::public::encode(&transaction.public_key_output),
        amount: transaction.amount,
        fee: transaction.fee,
        timestamp: transaction.timestamp,
        signature: hex::encode(transaction.signature),
    })?))
}
fn get_stake_by_hash(node: &mut Node, first: &str) -> Result<String, Box<dyn Error>> {
    let hash = hex::decode(
        STAKE_BY_HASH
            .find(first)
            .ok_or("GET STAKE_BY_HASH 1")?
            .as_str()
            .trim()
            .get(7..)
            .ok_or("GET STAKE_BY_HASH 2")?,
    )?;
    let stake = db::stake::get(&node.blockchain.db, &hash)?;
    Ok(json(serde_json::to_string(&get::Stake {
        hash: hex::encode(stake.hash()),
        public_key: address::public::encode(&stake.public_key),
        amount: stake.amount,
        deposit: stake.deposit,
        fee: stake.fee,
        timestamp: stake.timestamp,
        signature: hex::encode(stake.signature),
    })?))
}
fn get_peers(node: &mut Node) -> Result<String, Box<dyn Error>> {
    let peers = db::peer::get_all(&node.blockchain.db);
    Ok(json(serde_json::to_string(&peers)?))
}
fn post_transaction(node: &mut Node, buffer: &[u8; 1024]) -> Result<String, Box<dyn Error>> {
    let transaction: Transaction = bincode::deserialize(&hex::decode(
        buffer
            .lines()
            .nth(5)
            .ok_or("POST TRANSACTION 1")??
            .get(0..*TRANSACTION_SERIALIZED)
            .ok_or("POST TRANSACTION 2")?,
    )?)?;
    let data = bincode::serialize(&transaction).unwrap();
    let status = match node.blockchain.try_add_transaction(transaction, node.time.timestamp_secs()) {
        Ok(()) => {
            if node.gossipsub_has_mesh_peers("transaction") {
                node.gossipsub_publish("transaction", data);
            }
            "success".to_string()
        }
        Err(err) => {
            error!("{}", err);
            err.to_string()
        }
    };
    Ok(json(serde_json::to_string(&status)?))
}
fn post_stake(node: &mut Node, buffer: &[u8; 1024]) -> Result<String, Box<dyn Error>> {
    let stake: Stake = bincode::deserialize(&hex::decode(
        buffer.lines().nth(5).ok_or("POST STAKE 1")??.get(0..*STAKE_SERIALIZED).ok_or("POST STAKE 2")?,
    )?)?;
    let data = bincode::serialize(&stake).unwrap();
    let status = match node.blockchain.try_add_stake(stake, node.time.timestamp_secs()) {
        Ok(()) => {
            if node.gossipsub_has_mesh_peers("stake") {
                node.gossipsub_publish("stake", data);
            }
            "success".to_string()
        }
        Err(err) => {
            error!("{}", err);
            err.to_string()
        }
    };
    Ok(json(serde_json::to_string(&status)?))
}
fn c404() -> Result<String, Box<dyn Error>> {
    Ok("HTTP/1.1 404 Not Found".to_string())
}
fn c405() -> Result<String, Box<dyn Error>> {
    Ok("HTTP/1.1 405 Method Not Allowed".to_string())
}
