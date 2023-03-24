pub mod behaviour;
pub mod multiaddr;
use behaviour::Behaviour;
use libp2p::core::upgrade;
use libp2p::gossipsub::error::PublishError;
use libp2p::gossipsub::error::SubscriptionError;
use libp2p::gossipsub::IdentTopic;
use libp2p::gossipsub::TopicHash;
use libp2p::identity;
use libp2p::mplex;
use libp2p::noise;
use libp2p::swarm::ConnectionLimits;
use libp2p::swarm::SwarmBuilder;
use libp2p::tcp;
use libp2p::PeerId;
use libp2p::Swarm;
use libp2p::Transport;
use std::collections::HashMap;
use std::collections::HashSet;
use std::net::IpAddr;
use std::time::Duration;
use tofuri_core::*;
use tracing::log::warn;
#[derive(Debug)]
pub enum Error {
    PublishError(PublishError),
    Behaviour(behaviour::Error),
    SubscriptionError(SubscriptionError),
}
pub struct P2p {
    pub swarm: Swarm<Behaviour>,
    pub connections: HashMap<PeerId, IpAddr>,
    pub connections_unknown: HashSet<IpAddr>,
    pub connections_known: HashSet<IpAddr>,
    pub request_timeouts: HashMap<IpAddr, u32>,
    pub request_counter: HashMap<IpAddr, usize>,
    pub gossipsub_message_peers_counter: HashMap<IpAddr, usize>,
}
impl P2p {
    pub async fn new(max_established: Option<u32>, timeout: u64, known: HashSet<IpAddr>) -> Result<P2p, Error> {
        Ok(P2p {
            swarm: swarm(max_established, timeout).await?,
            connections: HashMap::new(),
            connections_unknown: HashSet::new(),
            connections_known: known,
            request_timeouts: HashMap::new(),
            request_counter: HashMap::new(),
            gossipsub_message_peers_counter: HashMap::new(),
        })
    }
    fn get_ip_addr(&self, peer_id: &PeerId) -> Option<IpAddr> {
        if let Some(ip_addr) = self.connections.get(peer_id).cloned() {
            Some(ip_addr)
        } else {
            warn!("Peer {} not found in connections", peer_id);
            None
        }
    }
    pub fn request_timeout(&mut self, peer_id: &PeerId) {
        if let Some(ip_addr) = self.get_ip_addr(peer_id) {
            self.request_timeouts.insert(ip_addr, tofuri_util::timestamp());
        }
    }
    pub fn request_counter(&mut self, peer_id: &PeerId) -> bool {
        if let Some(ip_addr) = self.get_ip_addr(peer_id) {
            let mut requests = *self.request_counter.get(&ip_addr).unwrap_or(&0);
            requests += 1;
            self.request_counter.insert(ip_addr, requests);
            if requests > P2P_REQUESTS {
                self.request_timeout(peer_id);
            }
            let timestamp = self.request_timeouts.get(&ip_addr).unwrap_or(&0);
            tofuri_util::timestamp() - timestamp < P2P_TIMEOUT
        } else {
            true
        }
    }
    pub fn gossipsub_message_peers_counter(&mut self, peer_id: &PeerId) -> bool {
        if let Some(ip_addr) = self.get_ip_addr(peer_id) {
            let mut peers = *self.gossipsub_message_peers_counter.get(&ip_addr).unwrap_or(&0);
            peers += 1;
            self.gossipsub_message_peers_counter.insert(ip_addr, peers);
            peers > P2P_PEERS
        } else {
            true
        }
    }
    fn gossipsub_has_mesh_peers(&self, topic: &str) -> bool {
        self.swarm.behaviour().gossipsub.mesh_peers(&TopicHash::from_raw(topic)).count() != 0
    }
    pub fn gossipsub_publish(&mut self, topic: &str, data: Vec<u8>) -> Result<(), Error> {
        if !self.gossipsub_has_mesh_peers(topic) {
            return Ok(());
        }
        self.swarm
            .behaviour_mut()
            .gossipsub
            .publish(IdentTopic::new(topic), data)
            .map_err(Error::PublishError)?;
        Ok(())
    }
}
async fn swarm(max_established: Option<u32>, timeout: u64) -> Result<Swarm<Behaviour>, Error> {
    let local_key = identity::Keypair::generate_ed25519();
    let local_peer_id = PeerId::from(local_key.public());
    let transport = tcp::tokio::Transport::new(tcp::Config::default().nodelay(true))
        .upgrade(upgrade::Version::V1)
        .authenticate(noise::NoiseAuthenticated::xx(&local_key).expect("Signing libp2p-noise static DH keypair failed."))
        .multiplex(mplex::MplexConfig::new())
        .timeout(Duration::from_millis(timeout))
        .boxed();
    let mut behaviour = Behaviour::new(local_key).await.map_err(Error::Behaviour)?;
    for ident_topic in [
        IdentTopic::new("block"),
        IdentTopic::new("stake"),
        IdentTopic::new("transaction"),
        IdentTopic::new("peers"),
    ]
    .iter()
    {
        behaviour.gossipsub.subscribe(ident_topic).map_err(Error::SubscriptionError)?;
    }
    let mut limits = ConnectionLimits::default();
    limits = limits.with_max_established_per_peer(Some(1));
    limits = limits.with_max_established(max_established);
    Ok(SwarmBuilder::with_tokio_executor(transport, behaviour, local_peer_id)
        .connection_limits(limits)
        .build())
}
