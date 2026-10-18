use serde::{Deserialize, Serialize};
use std::net::Ipv4Addr;

/// Connection metadata tracked in eBPF maps
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConnectionMetadata {
    pub start_ts_ns: u64,
    pub bytes_received: u64,
    pub bytes_sent: u64,
    pub original_dst_ip: Ipv4Addr,
    pub original_dst_port: u16,
    pub proxy_port: u16,
    pub intercepted: bool,
}

/// Mesh route rule programmed into kernel TC maps
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MeshRouteRule {
    pub target_subnet: Ipv4Addr,
    pub subnet_mask: Ipv4Addr,
    pub target_port: u16,
    pub redirect_enabled: bool,
    pub tls_enforced: bool,
}

impl MeshRouteRule {
    pub fn new(target_subnet: Ipv4Addr, subnet_mask: Ipv4Addr, target_port: u16) -> Self {
        Self {
            target_subnet,
            subnet_mask,
            target_port,
            redirect_enabled: true,
            tls_enforced: true,
        }
    }
}
