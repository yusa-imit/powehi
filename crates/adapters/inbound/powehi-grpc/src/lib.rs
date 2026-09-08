// Every fallible path in this adapter carries `tonic::Status` (176 bytes), either
// directly or through `GrpcError::Status`, which puts each `Result` over clippy's
// `result_large_err` threshold — a lint Rust 1.98 newly triggers on this code. The
// size belongs to tonic's type, not to ours, so boxing it here would only move the
// allocation without changing the gRPC contract.
#![allow(clippy::result_large_err)]

pub mod circuit;
pub mod client;
pub mod error;
pub mod server;
pub mod tls;

pub use client::RegionGrpcRouter;
pub use server::RegionGrpcServer;
pub use tls::TlsConfig;
