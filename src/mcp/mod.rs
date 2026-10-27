//! Remote MCP gateway that lets ChatGPT (or any OAuth MCP client) work on existing
//! T3 Code sessions. T3 stays the single source of conversations and runs.
pub mod events;
pub mod federation;
pub mod server;
pub mod store;
pub mod tools;
pub mod upstream;
pub mod webhook;
