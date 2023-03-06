use crate::Node;
use colored::*;
use libp2p::multiaddr::Protocol;
use libp2p::Multiaddr;
use rand::prelude::*;
use tofuri_core::*;
use tofuri_p2p::behaviour::SyncRequest;
use tofuri_p2p::multiaddr;
use tofuri_util;
use tokio::time::Instant;
use tracing::debug;
use tracing::error;
use tracing::info;
pub fn dial_known(node: &mut Node, instant: Instant) -> Instant {
    let vec = node.p2p.known.clone().into_iter().collect();
    dial(node, vec, true);
    instant
}
pub fn dial_unknown(node: &mut Node, instant: Instant) -> Instant {
    let vec = node.p2p.unknown.drain().collect();
    dial(node, vec, false);
    instant
}
pub fn clear(node: &mut Node, instant: Instant) -> Instant {
    node.blockchain.sync.handler();
    node.p2p.ratelimit.reset();
    node.p2p.filter.clear();
    instant
}
fn dial(node: &mut Node, vec: Vec<Multiaddr>, known: bool) {
    for mut multiaddr in vec {
        if node.p2p.connections.contains_key(&multiaddr::ip(&multiaddr).expect("multiaddr to include ip")) {
            continue;
        }
        let addr = multiaddr::ip_addr(&multiaddr).expect("multiaddr to include ip");
        if node.p2p.ratelimit.is_ratelimited(&node.p2p.ratelimit.get(&addr).1) {
            continue;
        }
        debug!(
            "Dialing {} peer {}",
            if known { "known".green() } else { "unknown".red() },
            multiaddr.to_string().magenta()
        );
        if !multiaddr::has_port(&multiaddr) {
            multiaddr.push(Protocol::Tcp(9333));
        }
        let _ = node.p2p.swarm.dial(multiaddr);
    }
}
pub fn share(node: &mut Node, instant: Instant) -> Instant {
    let vec: Vec<&Multiaddr> = node.p2p.connections.keys().collect();
    if let Err(err) = node.p2p.gossipsub_publish("multiaddr", bincode::serialize(&vec).unwrap()) {
        error!("{}", err);
    }
    instant
}
pub fn grow(node: &mut Node, instant: Instant) -> Instant {
    let timestamp = tofuri_util::timestamp();
    node.blockchain.pending_retain_non_ancient(timestamp);
    node.blockchain.save_blocks(&node.db, node.args.trust);
    if !node.blockchain.sync.downloading() && !node.args.mint && node.blockchain.states.dynamic.next_staker(timestamp).is_none() {
        if timestamp % 60 == 0 {
            info!(
                "Waiting for synchronization to start... Currently connected to {} peers.",
                node.p2p.connections.len().to_string().yellow()
            );
        }
        node.blockchain.sync.completed = false;
    }
    if !node.blockchain.sync.completed {
        return instant;
    }
    let diff = timestamp.saturating_sub(node.blockchain.states.dynamic.latest_block.timestamp);
    #[allow(clippy::modulo_one)]
    if diff == 0 || diff % BLOCK_TIME != 0 {
        return instant;
    }
    if let Some(staker) = node.blockchain.states.dynamic.next_staker(timestamp) {
        if staker != node.key.address_bytes() {
            return instant;
        }
    }
    let block_a = node.blockchain.forge_block(&node.db, &node.key, timestamp, node.args.trust);
    if let Err(err) = node.p2p.gossipsub_publish("block", bincode::serialize(&block_a.b()).unwrap()) {
        error!("{}", err);
    }
    instant
}
pub fn sync_request(node: &mut Node, instant: Instant) -> Instant {
    if let Some(peer_id) = node.p2p.swarm.connected_peers().choose(&mut thread_rng()).cloned() {
        node.p2p
            .swarm
            .behaviour_mut()
            .request_response
            .send_request(&peer_id, SyncRequest(bincode::serialize(&(node.blockchain.height())).unwrap()));
    }
    instant
}
