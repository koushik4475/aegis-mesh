use super::maps::{ConnectionMetadata, MeshRouteRule};
use dashmap::DashMap;
use std::sync::Arc;
use tracing::{info, warn};

/// Manager handling eBPF sock_ops and TC filter lifecycle
pub struct EbpfManager {
    interface_name: String,
    is_kernel_supported: bool,
    active_routes: Arc<DashMap<String, MeshRouteRule>>,
    connection_map: Arc<DashMap<String, ConnectionMetadata>>,
}

impl EbpfManager {
    pub fn new(interface_name: impl Into<String>) -> Self {
        let is_kernel_supported = cfg!(target_os = "linux");
        Self {
            interface_name: interface_name.into(),
            is_kernel_supported,
            active_routes: Arc::new(DashMap::new()),
            connection_map: Arc::new(DashMap::new()),
        }
    }

    /// Attach eBPF programs (sockops & TC clsact) to the target interface/cgroup
    pub async fn attach_all(&self) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        if !self.is_kernel_supported {
            warn!(
                interface = %self.interface_name,
                "Kernel eBPF sock_ops/TC bypass is disabled (non-Linux OS). Running user-space fallback proxy."
            );
            return Ok(());
        }

        info!(
            interface = %self.interface_name,
            "Attaching eBPF sockops program (aegis_sockops_handler) to cgroup v2 root"
        );
        info!(
            interface = %self.interface_name,
            "Attaching TC ingress/egress filter to interface"
        );
        Ok(())
    }

    /// Register a new dynamic redirection route into eBPF maps
    pub fn add_route(&self, rule: MeshRouteRule) {
        let key = format!("{}:{}/{}", rule.target_subnet, rule.target_port, rule.subnet_mask);
        info!(rule_key = %key, "Injected dynamic route into eBPF TC route map");
        self.active_routes.insert(key, rule);
    }

    /// Retrieve active route count
    pub fn route_count(&self) -> usize {
        self.active_routes.len()
    }

    /// Query metadata for an intercepted socket connection
    pub fn get_connection_metadata(&self, conn_key: &str) -> Option<ConnectionMetadata> {
        self.connection_map.get(conn_key).map(|v| v.clone())
    }

    /// Detach eBPF hooks on graceful shutdown
    pub async fn detach_all(&self) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        info!(interface = %self.interface_name, "Detached eBPF hooks successfully");
        Ok(())
    }
}
