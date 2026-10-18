use rcgen::{CertificateParams, DistinguishedName, DnType, KeyPair, SanType};
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use std::sync::Arc;
use tokio_rustls::rustls::{ClientConfig, RootCertStore, ServerConfig};
use tracing::info;

#[derive(Debug, Clone)]
pub struct MeshIdentity {
    pub service_name: String,
    pub namespace: String,
    pub trust_domain: String,
}

impl MeshIdentity {
    pub fn new(service_name: &str, namespace: &str, trust_domain: &str) -> Self {
        Self {
            service_name: service_name.to_string(),
            namespace: namespace.to_string(),
            trust_domain: trust_domain.to_string(),
        }
    }

    pub fn spiffe_id(&self) -> String {
        format!("spiffe://{}/ns/{}/sa/{}", self.trust_domain, self.namespace, self.service_name)
    }
}

/// Mutual TLS certificate manager supporting SPIFFE SAN identity generation
pub struct CertificateManager {
    identity: MeshIdentity,
    ca_cert: CertificateDer<'static>,
    server_cert: CertificateDer<'static>,
    server_key: PrivateKeyDer<'static>,
}

impl CertificateManager {
    /// Generate a production-ready self-signed CA and ephemeral SPIFFE certificate pair
    pub fn generate_ephemeral(identity: MeshIdentity) -> Result<Self, Box<dyn std::error::Error + Send + Sync>> {
        info!(spiffe_id = %identity.spiffe_id(), "Generating ephemeral mTLS identity certificate");

        // 1. Generate Root CA
        let mut ca_params = CertificateParams::default();
        let mut ca_dn = DistinguishedName::new();
        ca_dn.push(DnType::CommonName, format!("{} Root CA", identity.trust_domain));
        ca_dn.push(DnType::OrganizationName, "Aegis Zero-Trust Mesh");
        ca_params.distinguished_name = ca_dn;
        ca_params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
        let ca_key = KeyPair::generate()?;
        let ca_cert_obj = ca_params.self_signed(&ca_key)?;
        let ca_cert_der = CertificateDer::from(ca_cert_obj.der().to_vec());

        // 2. Generate Workload Certificate signed by CA
        let mut server_params = CertificateParams::default();
        let mut server_dn = DistinguishedName::new();
        server_dn.push(DnType::CommonName, identity.service_name.clone());
        server_params.distinguished_name = server_dn;
        server_params.subject_alt_names = vec![
            SanType::DnsName(identity.service_name.clone().try_into()?),
            SanType::DnsName("localhost".to_string().try_into()?),
            SanType::IpAddress(std::net::IpAddr::V4(std::net::Ipv4Addr::new(127, 0, 0, 1))),
            SanType::URI(identity.spiffe_id().try_into()?),
        ];

        let server_key_pair = KeyPair::generate()?;
        let server_cert_obj = server_params.signed_by(&server_key_pair, &ca_cert_obj, &ca_key)?;
        let server_cert_der = CertificateDer::from(server_cert_obj.der().to_vec());
        let server_key_der = PrivateKeyDer::Pkcs8(server_key_pair.serialize_der().into());

        Ok(Self {
            identity,
            ca_cert: ca_cert_der,
            server_cert: server_cert_der,
            server_key: server_key_der,
        })
    }

    /// Construct Rustls ServerConfig enforcing mTLS with client certificate verification
    pub fn build_server_config(&self) -> Result<Arc<ServerConfig>, Box<dyn std::error::Error + Send + Sync>> {
        let mut roots = RootCertStore::empty();
        roots.add(self.ca_cert.clone())?;

        let client_verifier = rustls::server::WebPkiClientVerifier::builder(Arc::new(roots))
            .build()?;

        let config = ServerConfig::builder()
            .with_client_cert_verifier(client_verifier)
            .with_single_cert(vec![self.server_cert.clone()], self.server_key.clone_key())?;

        Ok(Arc::new(config))
    }

    /// Construct Rustls ClientConfig for outbound mTLS calls between sidecars
    pub fn build_client_config(&self) -> Result<Arc<ClientConfig>, Box<dyn std::error::Error + Send + Sync>> {
        let mut roots = RootCertStore::empty();
        roots.add(self.ca_cert.clone())?;

        let config = ClientConfig::builder()
            .with_root_certificates(roots)
            .with_client_auth_cert(vec![self.server_cert.clone()], self.server_key.clone_key())?;

        Ok(Arc::new(config))
    }

    pub fn identity(&self) -> &MeshIdentity {
        &self.identity
    }
}
