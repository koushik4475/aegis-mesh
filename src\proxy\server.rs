use super::cert::CertificateManager;
use super::limiter::TokenBucketLimiter;
use super::validator::TokenValidator;
use crate::policy::engine::{PolicyDecision, PolicyEngine, RequestContext};
use bytes::Bytes;
use http_body_util::combinators::BoxBody;
use http_body_util::{BodyExt, Empty, Full};
use hyper::server::conn::http1;
use hyper::service::service_fn;
use hyper::{Method, Request, Response, StatusCode};
use hyper_util::rt::TokioIo;
use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::net::TcpListener;
use tokio_rustls::TlsAcceptor;
use tracing::{error, info, warn};

#[derive(Clone)]
pub struct AegisProxyConfig {
    pub bind_addr: SocketAddr,
    pub upstream_addr: Option<SocketAddr>,
    pub enforce_mtls: bool,
    pub enforce_tokens: bool,
}

/// Production-ready Aegis Zero-Trust Sidecar Proxy
pub struct AegisProxy {
    config: AegisProxyConfig,
    policy_engine: Arc<PolicyEngine>,
    token_validator: Arc<TokenValidator>,
    rate_limiter: Arc<TokenBucketLimiter>,
    cert_manager: Option<Arc<CertificateManager>>,
}

impl AegisProxy {
    pub fn new(
        config: AegisProxyConfig,
        policy_engine: Arc<PolicyEngine>,
        token_validator: Arc<TokenValidator>,
        rate_limiter: Arc<TokenBucketLimiter>,
        cert_manager: Option<Arc<CertificateManager>>,
    ) -> Self {
        Self {
            config,
            policy_engine,
            token_validator,
            rate_limiter,
            cert_manager,
        }
    }

    /// Start the proxy listener and dispatch connections
    pub async fn run(&self) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let listener = TcpListener::bind(self.config.bind_addr).await?;
        info!(
            bind = %self.config.bind_addr,
            mtls = self.config.enforce_mtls,
            "Aegis Mesh Sidecar Proxy listening for connections"
        );

        let tls_acceptor = if self.config.enforce_mtls {
            if let Some(ref cert_mgr) = self.cert_manager {
                Some(TlsAcceptor::from(cert_mgr.build_server_config()?))
            } else {
                return Err("mTLS requested but CertificateManager not provided".into());
            }
        } else {
            None
        };

        loop {
            let (stream, peer_addr) = match listener.accept().await {
                Ok(conn) => conn,
                Err(e) => {
                    warn!(error = %e, "Failed accepting TCP connection");
                    continue;
                }
            };

            let policy_engine = Arc::clone(&self.policy_engine);
            let token_validator = Arc::clone(&self.token_validator);
            let rate_limiter = Arc::clone(&self.rate_limiter);
            let config = self.config.clone();
            let acceptor = tls_acceptor.clone();

            tokio::spawn(async move {
                if let Some(acceptor) = acceptor {
                    match acceptor.accept(stream).await {
                        Ok(tls_stream) => {
                            let io = TokioIo::new(tls_stream);
                            let service = service_fn(move |req| {
                                Self::handle_request(
                                    req,
                                    peer_addr,
                                    Arc::clone(&policy_engine),
                                    Arc::clone(&token_validator),
                                    Arc::clone(&rate_limiter),
                                    config.clone(),
                                )
                            });

                            if let Err(err) = http1::Builder::new().serve_connection(io, service).await {
                                error!(error = %err, "Error serving mTLS HTTP connection");
                            }
                        }
                        Err(e) => {
                            warn!(error = %e, peer = %peer_addr, "mTLS handshake failed");
                        }
                    }
                } else {
                    let io = TokioIo::new(stream);
                    let service = service_fn(move |req| {
                        Self::handle_request(
                            req,
                            peer_addr,
                            Arc::clone(&policy_engine),
                            Arc::clone(&token_validator),
                            Arc::clone(&rate_limiter),
                            config.clone(),
                        )
                    });

                    if let Err(err) = http1::Builder::new().serve_connection(io, service).await {
                        error!(error = %err, "Error serving plain HTTP connection");
                    }
                }
            });
        }
    }

    /// Process HTTP request through Auth validation, Policy evaluation, and Rate limiting
    pub async fn handle_request(
        req: Request<hyper::body::Incoming>,
        peer_addr: SocketAddr,
        policy_engine: Arc<PolicyEngine>,
        token_validator: Arc<TokenValidator>,
        rate_limiter: Arc<TokenBucketLimiter>,
        config: AegisProxyConfig,
    ) -> Result<Response<BoxBody<Bytes, hyper::Error>>, hyper::Error> {
        let method = req.method().to_string();
        let path = req.uri().path().to_string();

        // 1. Healthcheck shortcut
        if path == "/healthz" || path == "/livez" {
            let body = Full::new(Bytes::from("OK\n")).map_err(|e| match e {})
                .boxed();
            return Ok(Response::builder()
                .status(StatusCode::OK)
                .body(body)
                .unwrap());
        }

        // 2. Token extraction & validation
        let mut roles = Vec::new();
        let mut claims = HashMap::new();
        let mut client_sub = None;

        if let Some(auth_val) = req.headers().get("Authorization").and_then(|h| h.to_str().ok()) {
            match token_validator.validate_header(auth_val) {
                Ok(auth_claims) => {
                    client_sub = Some(auth_claims.sub.clone());
                    roles = auth_claims.roles;
                    claims = auth_claims.custom;
                }
                Err(err) => {
                    if config.enforce_tokens {
                        let err_msg = format!("{{\"error\": \"Unauthorized\", \"details\": \"{}\"}}\n", err);
                        return Ok(Response::builder()
                            .status(StatusCode::UNAUTHORIZED)
                            .header("Content-Type", "application/json")
                            .body(Full::new(Bytes::from(err_msg)).map_err(|e| match e {}).boxed())
                            .unwrap());
                    }
                }
            }
        } else if config.enforce_tokens {
            let err_msg = "{\"error\": \"Unauthorized\", \"details\": \"Missing Authorization header\"}\n";
            return Ok(Response::builder()
                .status(StatusCode::UNAUTHORIZED)
                .header("Content-Type", "application/json")
                .body(Full::new(Bytes::from(err_msg)).map_err(|e| match e {}).boxed())
                .unwrap());
        }

        // 3. Build Request Context
        let ctx = RequestContext {
            client_identity: client_sub.clone(),
            roles,
            claims,
            method: method.clone(),
            path: path.clone(),
            source_ip: peer_addr.ip().to_string(),
        };

        // 4. Policy Engine Evaluation
        let decision = policy_engine.evaluate(&ctx);
        match decision {
            PolicyDecision::Deny { reason } => {
                let err_msg = format!("{{\"error\": \"Forbidden\", \"reason\": \"{}\"}}\n", reason);
                return Ok(Response::builder()
                    .status(StatusCode::FORBIDDEN)
                    .header("Content-Type", "application/json")
                    .body(Full::new(Bytes::from(err_msg)).map_err(|e| match e {}).boxed())
                    .unwrap());
            }
            PolicyDecision::RateLimit { rule_name, limit_rps } => {
                let limiter_key = client_sub.unwrap_or_else(|| peer_addr.ip().to_string());
                if !rate_limiter.check_allowed(&limiter_key, Some(limit_rps)) {
                    let err_msg = format!(
                        "{{\"error\": \"Too Many Requests\", \"rule\": \"{}\", \"limit_rps\": {}}}\n",
                        rule_name, limit_rps
                    );
                    return Ok(Response::builder()
                        .status(StatusCode::TOO_MANY_REQUESTS)
                        .header("Content-Type", "application/json")
                        .body(Full::new(Bytes::from(err_msg)).map_err(|e| match e {}).boxed())
                        .unwrap());
                }
            }
            PolicyDecision::Allow { .. } => {
                // Check general rate limiter
                let limiter_key = client_sub.unwrap_or_else(|| peer_addr.ip().to_string());
                if !rate_limiter.check_allowed(&limiter_key, None) {
                    let err_msg = "{\"error\": \"Too Many Requests\", \"limit\": \"general\"}\n";
                    return Ok(Response::builder()
                        .status(StatusCode::TOO_MANY_REQUESTS)
                        .header("Content-Type", "application/json")
                        .body(Full::new(Bytes::from(err_msg)).map_err(|e| match e {}).boxed())
                        .unwrap());
                }
            }
        }

        // 5. Success proxy response
        let resp_json = format!(
            "{{\"status\": \"aegis_mesh_authorized\", \"method\": \"{}\", \"path\": \"{}\", \"source\": \"{}\"}}\n",
            method, path, peer_addr
        );

        Ok(Response::builder()
            .status(StatusCode::OK)
            .header("Content-Type", "application/json")
            .header("X-Aegis-Mesh-Verdict", "Authorized")
            .body(Full::new(Bytes::from(resp_json)).map_err(|e| match e {}).boxed())
            .unwrap())
    }
}
