<div align="center">

# Aegis Mesh | Zero-Trust API Security Sidecar with Rust and eBPF

Aegis Mesh is a Rust-based security-mesh prototype for enforcing zero-trust policies around service-to-service API traffic. The README describes an eBPF-assisted sidecar proxy, workload identity, and mTLS-oriented policy enforcement for Linux workloads. It is intended for developers exploring kernel networking, service identity, and API security architecture; validate kernel compatibility and policies in a test environment before deployment.


### Zero-Trust Kernel-Enforced API Security Mesh & Sidecar Proxy with eBPF

[![CI Pipeline](https://github.com/ER-brocode/aegis-mesh/actions/workflows/ci.yml/badge.svg)](https://github.com/ER-brocode/aegis-mesh/actions)
[![License](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](LICENSE)
[![Rust](https://img.shields.io/badge/Rust-1.78%2B-orange.svg)](https://www.rust-lang.org)
[![eBPF](https://img.shields.io/badge/eBPF-sock__ops%20%7C%20TC-green.svg)](https://ebpf.io)
[![Zero-Trust](https://img.shields.io/badge/Zero--Trust-SPIFFE%2FmTLS-purple.svg)](https://spiffe.io)

<p align="center">
  <b>High-velocity zero-trust API protection bypassing TCP stack overhead via kernel eBPF sockmap redirection and hardware-grade cryptographic identity verification.</b>
</p>

```
  +-----------------------------------------------------------------------------------------+
  |                               Workload Pod / Namespace                                  |
  |                                                                                         |
  |   +-------------------+                     +---------------------------------------+   |
  |   | Application Logic |                     |           Aegis Sidecar Proxy         |   |
  |   | (REST/gRPC micro) |                     |  - Token Validator (JWT / RBAC)       |   |
  |   +---------+---------+                     |  - High-precision Token Bucket Rate   |   |
  |             |                               |  - Ephemeral SPIFFE/mTLS TLS Engine   |   |
  |             |                               +-------------------+-------------------+   |
  +-------------|---------------------------------------------------|-----------------------+
  | KERNEL      |                                                   |                       |
  |             v                                                   v                       |
  |   +-----------------------+   bpf_msg_redirect_hash   +-------------------+             |
  |   | eBPF sock_ops Hook    | ========================> |  eBPF TC Ingress  |             |
  |   | (cgroup v2 sk_lookup) |    Zero TCP Stack Copy    |  (clsact filter)  |             |
  |   +-----------------------+                           +-------------------+             |
  +-----------------------------------------------------------------------------------------+
```

</div>

---

## 🌟 Key Features

- **⚡ Kernel-Level Socket Redirection (eBPF `sock_ops` & `sk_msg`)**: Intercepts TCP connection establishments and redirects data payloads directly to sidecar sockets across pods, bypassing network stack overhead and eliminating iptables routing complexity.
- **🔒 True Zero-Trust Architecture**: Default-deny security model requiring explicit declarative route authorization, role verification, and cryptographic identity attestation.
- **🛡️ Ephemeral Mutual TLS (mTLS) with SPIFFE ID**: Automated X.509 certificate provisioning with dynamic SAN URI generation (`spiffe://<domain>/ns/<namespace>/sa/<service>`).
- **🎫 Dynamic JWT & Claims Validation**: Sub-millisecond JWT token validation enforcing issuer, audience, role membership, and custom claims at the ingress gateway.
- **⏱️ Lock-Free Dynamic Rate Limiting**: DashMap-backed thread-safe token bucket algorithm enforcing per-tenant and per-endpoint RPS quotas with zero thread contention.
- **🔄 Hot-Reloadable Security Policies**: Update RBAC and routing policies dynamically on the fly with zero connection drops.

---

## 📁 Repository Structure

```
aegis-mesh/
├── Cargo.toml                    # Rust workspace manifest & crate dependencies
├── bpf/                          # High-performance eBPF C programs
│   ├── aegis_sockops.bpf.c       # Kernel sock_ops & sk_msg redirection hook
│   └── aegis_tc_filter.bpf.c     # Ingress/egress TC clsact filter for packets
├── src/
│   ├── lib.rs                    # Mesh library root exports
│   ├── main.rs                   # Aegis daemon CLI entrypoint
│   ├── ebpf/                     # eBPF loader, abstraction maps & management
│   │   ├── mod.rs
│   │   ├── loader.rs
│   │   └── maps.rs
│   ├── policy/                   # Policy evaluation engine & RBAC
│   │   ├── mod.rs
│   │   ├── engine.rs
│   │   ├── matcher.rs
│   │   └── model.rs
│   └── proxy/                    # Zero-trust mTLS proxy & auth validation
│       ├── mod.rs
│       ├── cert.rs
│       ├── limiter.rs
│       ├── server.rs
│       └── validator.rs
├── tests/                        # Integration and verification test suites
│   ├── mtls_tests.rs             # Mutual TLS & certificate verification tests
│   └── policy_tests.rs           # RBAC and zero-trust policy engine tests
├── config/
│   └── mesh-config.yaml          # Declarative production mesh configuration
└── .github/workflows/
    └── ci.yml                    # Automated build, clippy, unit test & BPF CI
```

---

## 🚀 Quick Start

### 1. Build and Run Sidecar Proxy
```bash
# Clone the repository
git clone https://github.com/ER-brocode/aegis-mesh.git
cd aegis-mesh

# Run the proxy daemon in development mode
cargo run -- --proxy-port 127.0.0.1:15001 --service-name order-service --namespace production
```

### 2. Run Test Suites
```bash
cargo test --verbose
```

### 3. Compile eBPF Bytecode
```bash
clang -O2 -g -target bpf -c bpf/aegis_sockops.bpf.c -o bpf/aegis_sockops.o
clang -O2 -g -target bpf -c bpf/aegis_tc_filter.bpf.c -o bpf/aegis_tc.o
```

---

## 🔐 Declarative Security Policy Example

```yaml
version: "v1"
mesh:
  name: "aegis-production-mesh"
  trust_domain: "cluster.local"
policy:
  default_action: "deny"
  rules:
    - name: "system-probes"
      paths: ["/healthz", "/livez"]
      methods: ["GET"]
      action: "allow"
      priority: 100
    - name: "order-management"
      paths: ["/api/v1/orders/**"]
      methods: ["GET", "POST"]
      required_roles: ["order-operator", "mesh-admin"]
      action: "allow"
      priority: 50
    - name: "sensitive-vault-access"
      paths: ["/vault/**"]
      methods: ["*"]
      required_roles: ["vault-admin"]
      action: "allow"
      priority: 10
      rate_limit_rps: 10
```

---

## 📜 License

Licensed under the Apache License, Version 2.0. See [LICENSE](LICENSE) for details.

---

<div align="center">
  Maintained with ❤️ by <b><a href="https://github.com/koushik4475">koushik4475</a></b> and the <b>ER-brocode</b> organization.
</div>
