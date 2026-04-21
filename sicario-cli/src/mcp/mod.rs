//! Model Context Protocol (MCP) server module
//!
//! Implements the MCP specification for AI agent integration, exposing
//! security scanning capabilities through JSON-RPC 2.0 over TCP.
//!
//! Requirements: 6.1, 6.2, 6.3, 6.4, 6.5

pub mod protocol;
pub mod server;
pub mod assistant_memory;

#[cfg(test)]
mod mcp_property_tests;

pub use server::McpServer;
pub use protocol::{McpRequest, McpResponse, JsonRpcError};
pub use assistant_memory::AssistantMemory;
