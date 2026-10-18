use aegis_mesh::ebpf::EbpfManager;
use aegis_mesh::policy::engine::PolicyEngine;
use aegis_mesh::policy::model::{Action, PolicyRule, SecurityPolicy};
use aegis_mesh::proxy::cert::{CertificateManager, MeshIdentity};
use aegis_mesh::proxy::limiter::TokenBucketLimiter;
use aegis_mesh::proxy::server::{AegisProxy, AegisProxyConfig};
use aegis_mesh::proxy::validator::TokenValidator;
use clap::Parser;
use std::net::SocketAddr;
use std::sync::Arc;
use tracing::info;
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};

#[derive(Parser, Debug)]
#[command(author = "koushik4475", version = "0.1.0", about = "Zero-Trust Kernel-Enforced API Security Mesh")]
struct Args {
    #[arg(short, long, default_value = "127.0.0.1:15001")]
    proxy_port: SocketAddr,

    #[arg(long, default_value = "order-service")]
    service_name: String,

    #[arg(long, default_value = "production")]
    namespace: String,

    #[arg(long, default_value = "cluster.local")]
    trust_domain: String,

    #[arg(long, default_value = "eth0")]
    interface: String,

    #[arg(long, default_value_t = false)]
    enforce_mtls: bool,

    #[arg(long, default_value_t = false)]
    enforce_tokens: bool,
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    tracing_subscriber::registry()
        .with(tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| "info".into()))
        .with(tracing_subscriber::fmt::layer())
        .init();

    let args = Args::parse();

    println!(r#"
    ___    ______ _____  ________       __  _________   __  __
   /   |  / ____// ___/ /  _/ ___/      /  |/  / ____/  / / / /
  / /| | / __/  / (_ /  / / \__ \ ____ / /|_/ / __/    / /_/ / 
 / ___ |/ /___  / /__/ /_/ /___/ //___// /  / / /___   / __  /  
/_/  |_/_____/  \___//___//____/      /_/  /_/_____/  /_/ /_/   
 Zero-Trust Kernel-Enforced API Security Mesh & Sidecar Proxy
    "#);

    info!(
        service = %args.service_name,
        namespace = %args.namespace,
        listen = %args.proxy_port,
        "Initializing Aegis Mesh Daemon"
    );

    // 1. Initialize eBPF Subsystem
    let ebpf_mgr = Arc::new(EbpfManager::new(&args.interface));
    ebpf_mgr.attach_all().await?;

    // 2. Setup Security Policy
    let mut default_policy = SecurityPolicy {
        version: "v1".to_string(),
        service_name: args.service_name.clone(),
        default_action: Action::Deny,
        rules: vec![
            PolicyRule {
                name: "allow-metrics-and-health".into(),
                description: Some("Public monitoring endpoints".into()),
                paths: vec!["/healthz".into(), "/livez".into(), "/metrics".into()],
                methods: vec!["GET".into()],
                required_roles: vec![],
                required_claims: None,
                action: Action::Allow,
                priority: 100,
                rate_limit_rps: None,
            },
            PolicyRule {
                name: "api-read-access".into(),
                description: Some("Read permissions for operators and viewers".into()),
                paths: vec!["/api/v1/**".into()],
                methods: vec!["GET".into()],
                required_roles: vec!["viewer".into(), "operator".into(), "admin".into()],
                required_claims: None,
                action: Action::Allow,
                priority: 50,
                rate_limit_rps: None,
            },
            PolicyRule {
                name: "api-write-restricted".into(),
                description: Some("Write modifications restricted to admin".into()),
                paths: vec!["/api/v1/**".into()],
                methods: vec!["POST".into(), "PUT".into(), "DELETE".into()],
                required_roles: vec!["admin".into()],
                required_claims: None,
                action: Action::Allow,
                priority: 40,
                rate_limit_rps: Some(25),
            },
        ],
    };

    let policy_engine = Arc::new(PolicyEngine::new(default_policy));
    let token_validator = Arc::new(TokenValidator::new(
        "aegis-mesh-zero-trust-shared-secret-key-256",
        "aegis.mesh.idp",
        "aegis.mesh.services",
    ));
    let rate_limiter = Arc::new(TokenBucketLimiter::new(100, 50));

    let identity = MeshIdentity::new(&args.service_name, &args.namespace, &args.trust_domain);
    let cert_manager = Arc::new(CertificateManager::generate_ephemeral(identity)?);

    let proxy_config = AegisProxyConfig {
        bind_addr: args.proxy_port,
        upstream_addr: None,
        enforce_mtls: args.enforce_mtls,
        enforce_tokens: args.enforce_tokens,
    };

    let proxy = AegisProxy::new(
        proxy_config,
        policy_engine,
        token_validator,
        rate_limiter,
        Some(cert_manager),
    );

    info!("Starting Aegis Proxy server loop...");
    proxy.run().await?;

    Ok(())
}
