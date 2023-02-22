use crate::Args;
use axum::extract::Path;
use axum::extract::State;
use axum::response::IntoResponse;
use axum::Json;
use multiaddr::Multiaddr;
use pea_address::address;
use pea_api_core::Root;
use pea_api_core::Stake;
use pea_api_core::Transaction;
use pea_core::*;
pub async fn root(State(args): State<Args>) -> impl IntoResponse {
    let cargo_pkg_name = pea_api_internal::cargo_pkg_name(&args.api_internal).await.unwrap();
    let cargo_pkg_version = pea_api_internal::cargo_pkg_version(&args.api_internal).await.unwrap();
    let cargo_pkg_repository = pea_api_internal::cargo_pkg_repository(&args.api_internal).await.unwrap();
    let git_hash = pea_api_internal::git_hash(&args.api_internal).await.unwrap();
    Json(Root {
        cargo_pkg_name,
        cargo_pkg_version,
        cargo_pkg_repository,
        git_hash,
    })
}
pub async fn balance(State(args): State<Args>, address: Path<String>) -> impl IntoResponse {
    let address_bytes = address::decode(&address).unwrap();
    let balance = pea_int::to_string(pea_api_internal::balance(&args.api_internal, &address_bytes).await.unwrap());
    Json(balance)
}
pub async fn balance_pending_min(State(args): State<Args>, address: Path<String>) -> impl IntoResponse {
    let address_bytes = address::decode(&address).unwrap();
    let balance_pending_min = pea_int::to_string(pea_api_internal::balance_pending_min(&args.api_internal, &address_bytes).await.unwrap());
    Json(balance_pending_min)
}
pub async fn balance_pending_max(State(args): State<Args>, address: Path<String>) -> impl IntoResponse {
    let address_bytes = address::decode(&address).unwrap();
    let balance_pending_max = pea_int::to_string(pea_api_internal::balance_pending_max(&args.api_internal, &address_bytes).await.unwrap());
    Json(balance_pending_max)
}
pub async fn staked(State(args): State<Args>, address: Path<String>) -> impl IntoResponse {
    let address_bytes = address::decode(&address).unwrap();
    let staked = pea_int::to_string(pea_api_internal::staked(&args.api_internal, &address_bytes).await.unwrap());
    Json(staked)
}
pub async fn staked_pending_min(State(args): State<Args>, address: Path<String>) -> impl IntoResponse {
    let address_bytes = address::decode(&address).unwrap();
    let staked_pending_min = pea_int::to_string(pea_api_internal::staked_pending_min(&args.api_internal, &address_bytes).await.unwrap());
    Json(staked_pending_min)
}
pub async fn staked_pending_max(State(args): State<Args>, address: Path<String>) -> impl IntoResponse {
    let address_bytes = address::decode(&address).unwrap();
    let staked_pending_max = pea_int::to_string(pea_api_internal::staked_pending_max(&args.api_internal, &address_bytes).await.unwrap());
    Json(staked_pending_max)
}
pub async fn height(State(args): State<Args>) -> impl IntoResponse {
    let height = pea_api_internal::height(&args.api_internal).await.unwrap();
    Json(height)
}
pub async fn height_by_hash(State(args): State<Args>, hash: Path<String>) -> impl IntoResponse {
    let hash: Hash = hex::decode(hash.clone()).unwrap().try_into().unwrap();
    let height = pea_api_internal::height_by_hash(&args.api_internal, &hash).await.unwrap();
    Json(height)
}
pub async fn block_latest(State(args): State<Args>) -> impl IntoResponse {
    let block_a = pea_api_internal::block_latest(&args.api_internal).await.unwrap();
    let block = pea_api_util::block(&block_a);
    Json(block)
}
pub async fn hash_by_height(State(args): State<Args>, height: Path<String>) -> impl IntoResponse {
    let height: usize = height.parse().unwrap();
    let hash = hex::encode(pea_api_internal::hash_by_height(&args.api_internal, &height).await.unwrap());
    Json(hash)
}
pub async fn block_by_hash(State(args): State<Args>, hash: Path<String>) -> impl IntoResponse {
    let hash: Hash = hex::decode(hash.clone()).unwrap().try_into().unwrap();
    let block_a = pea_api_internal::block_by_hash(&args.api_internal, &hash).await.unwrap();
    let block = pea_api_util::block(&block_a);
    Json(block)
}
pub async fn transaction_by_hash(State(args): State<Args>, hash: Path<String>) -> impl IntoResponse {
    let hash: Hash = hex::decode(hash.clone()).unwrap().try_into().unwrap();
    let transaction_a = pea_api_internal::transaction_by_hash(&args.api_internal, &hash).await.unwrap();
    let transaction = pea_api_util::transaction(&transaction_a);
    Json(transaction)
}
pub async fn stake_by_hash(State(args): State<Args>, hash: Path<String>) -> impl IntoResponse {
    let hash: Hash = hex::decode(hash.clone()).unwrap().try_into().unwrap();
    let stake_a = pea_api_internal::stake_by_hash(&args.api_internal, &hash).await.unwrap();
    let stake = pea_api_util::stake(&stake_a);
    Json(stake)
}
pub async fn peers(State(args): State<Args>) -> impl IntoResponse {
    let peers = pea_api_internal::peers(&args.api_internal).await.unwrap();
    Json(peers)
}
pub async fn peer_multiaddr_ip_port(State(args): State<Args>, Path((a, b, c, d)): Path<(String, String, String, String)>) -> impl IntoResponse {
    let string = format!("/{}/{}/{}/{}", a, b, c, d);
    let multiaddr: Multiaddr = string.parse().unwrap();
    pea_api_internal::peer(&args.api_internal, &multiaddr).await.unwrap();
    Json(true)
}
pub async fn peer_multiaddr_ip(State(args): State<Args>, Path((a, b)): Path<(String, String)>) -> impl IntoResponse {
    let string = format!("/{}/{}", a, b);
    let multiaddr: Multiaddr = string.parse().unwrap();
    pea_api_internal::peer(&args.api_internal, &multiaddr).await.unwrap();
    Json(true)
}
pub async fn transaction(State(args): State<Args>, Json(transaction): Json<Transaction>) -> impl IntoResponse {
    let transaction_b = pea_api_util::transaction_b(&transaction).unwrap();
    let status = pea_api_internal::transaction(&args.api_internal, &transaction_b).await.unwrap();
    Json(status)
}
pub async fn stake(State(args): State<Args>, Json(stake): Json<Stake>) -> impl IntoResponse {
    let stake_b = pea_api_util::stake_b(&stake).unwrap();
    let status = pea_api_internal::stake(&args.api_internal, &stake_b).await.unwrap();
    Json(status)
}
pub async fn cargo_pkg_name(State(args): State<Args>) -> impl IntoResponse {
    let cargo_pkg_name = pea_api_internal::cargo_pkg_name(&args.api_internal).await.unwrap();
    Json(cargo_pkg_name)
}
pub async fn cargo_pkg_version(State(args): State<Args>) -> impl IntoResponse {
    let cargo_pkg_version = pea_api_internal::cargo_pkg_version(&args.api_internal).await.unwrap();
    Json(cargo_pkg_version)
}
pub async fn cargo_pkg_repository(State(args): State<Args>) -> impl IntoResponse {
    let cargo_pkg_repository = pea_api_internal::cargo_pkg_repository(&args.api_internal).await.unwrap();
    Json(cargo_pkg_repository)
}
pub async fn git_hash(State(args): State<Args>) -> impl IntoResponse {
    let git_hash = pea_api_internal::git_hash(&args.api_internal).await.unwrap();
    Json(git_hash)
}
pub async fn address(State(args): State<Args>) -> impl IntoResponse {
    let address = pea_api_internal::address(&args.api_internal).await.unwrap();
    let address = address::encode(&address);
    Json(address)
}
pub async fn ticks(State(args): State<Args>) -> impl IntoResponse {
    let ticks = pea_api_internal::ticks(&args.api_internal).await.unwrap();
    Json(ticks)
}
pub async fn lag(State(args): State<Args>) -> impl IntoResponse {
    let lag = pea_api_internal::lag(&args.api_internal).await.unwrap();
    Json(lag)
}
pub async fn time(State(args): State<Args>) -> impl IntoResponse {
    let time = pea_api_internal::time(&args.api_internal).await.unwrap();
    Json(time)
}
pub async fn tree_size(State(args): State<Args>) -> impl IntoResponse {
    let tree_size = pea_api_internal::tree_size(&args.api_internal).await.unwrap();
    Json(tree_size)
}
pub async fn sync(State(args): State<Args>) -> impl IntoResponse {
    let sync = pea_api_internal::sync(&args.api_internal).await.unwrap();
    Json(sync)
}
pub async fn random_queue(State(args): State<Args>) -> impl IntoResponse {
    let random_queue = pea_api_internal::random_queue(&args.api_internal).await.unwrap();
    let random_queue: Vec<String> = random_queue.iter().map(address::encode).collect();
    Json(random_queue)
}
pub async fn dynamic_hashes(State(args): State<Args>) -> impl IntoResponse {
    let dynamic_hashes = pea_api_internal::dynamic_hashes(&args.api_internal).await.unwrap();
    Json(dynamic_hashes)
}
pub async fn dynamic_latest_hashes(State(args): State<Args>) -> impl IntoResponse {
    let dynamic_latest_hashes = pea_api_internal::dynamic_latest_hashes(&args.api_internal).await.unwrap();
    let dynamic_latest_hashes: Vec<String> = dynamic_latest_hashes.iter().map(hex::encode).collect();
    Json(dynamic_latest_hashes)
}
pub async fn dynamic_stakers(State(args): State<Args>) -> impl IntoResponse {
    let dynamic_stakers = pea_api_internal::dynamic_stakers(&args.api_internal).await.unwrap();
    Json(dynamic_stakers)
}
pub async fn trusted_hashes(State(args): State<Args>) -> impl IntoResponse {
    let trusted_hashes = pea_api_internal::trusted_hashes(&args.api_internal).await.unwrap();
    Json(trusted_hashes)
}
pub async fn trusted_latest_hashes(State(args): State<Args>) -> impl IntoResponse {
    let trusted_latest_hashes = pea_api_internal::trusted_latest_hashes(&args.api_internal).await.unwrap();
    let trusted_latest_hashes: Vec<String> = trusted_latest_hashes.iter().map(hex::encode).collect();
    Json(trusted_latest_hashes)
}
pub async fn trusted_stakers(State(args): State<Args>) -> impl IntoResponse {
    let trusted_stakers = pea_api_internal::trusted_stakers(&args.api_internal).await.unwrap();
    Json(trusted_stakers)
}
pub async fn sync_remaining(State(args): State<Args>) -> impl IntoResponse {
    let sync = pea_api_internal::sync(&args.api_internal).await.unwrap();
    if sync.completed {
        return Json(0.0);
    }
    if !sync.downloading() {
        return Json(-1.0);
    }
    let block_a = pea_api_internal::block_latest(&args.api_internal).await.unwrap();
    let mut diff = pea_util::timestamp().saturating_sub(block_a.timestamp) as f32;
    diff /= BLOCK_TIME as f32;
    diff /= sync.bps;
    Json(diff)
}
