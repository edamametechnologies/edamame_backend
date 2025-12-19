# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

EDAMAME Backend is a Rust library providing data structures for communication between EDAMAME agents and the EDAMAME Hub backend. It defines serializable types for threat detection, network scanning, agentic analysis, and security advisories.

Part of the EDAMAME ecosystem - see `../edamame_core/CLAUDE.md` for full ecosystem documentation.

## Build Commands

```bash
cargo build
cargo test
cargo fmt
```

## Architecture

This is a pure data serialization library with no runtime logic. All structs derive `Debug, Clone, Serialize, Deserialize`.

### Modules

| Module | Purpose |
|--------|---------|
| `agentic_backend.rs` | LLM analysis requests and decisions |
| `threat_backend.rs` | Threat metrics with multi-locale descriptions |
| `lanscan_device_info_backend.rs` | Device vendor, mDNS services, vulnerabilities |
| `lanscan_port_info_backend.rs` | Port scanning results |
| `lanscan_vulnerability_info_backend.rs` | Vulnerability data |
| `session_info_backend.rs` | IP, port, protocol, ASN, service, process info |
| `advisor_todos_backend.rs` | Advisory recommendations |
| `order_backend.rs` | Metric order results with validation |
| `score_backend.rs` | Scoring mechanisms |
| `history_backend.rs` | Historical data tracking |
| `policy_backend.rs` | Policy definitions |
| `pwned_backend.rs` | Password compromise detection |
| `signature.rs` | HMAC-SHA256 signature verification |
| `version.rs` | Backend version management |

### Key Patterns

- Structs implement `uid()` methods generating unique identifiers via BLAKE3 hashing
- Signature verification supports versions 0.3.3+
- All types are designed for JSON serialization

## Dependencies

- `serde` - JSON serialization
- `blake3` - Fast hashing for UIDs
- `hmac`, `sha2` - Signature verification
- `chrono` - Timestamp handling

## Local Development

Use `../edamame_app/flip.sh local` to switch to local path dependencies.
