use std::future::Future;
use std::pin::Pin;

use super::ToolCall;
use super::memory::ToolResult;
use super::observation::Observation;

/// Boundary the agent uses to read game state and execute tools.
///
/// For v1 we will run the agent loop inside the gateway proxy process; the proxy will implement this trait.
pub trait GameApi: Send + Sync {
    fn observe<'a>(
        &'a self,
    ) -> Pin<Box<dyn Future<Output = anyhow::Result<Observation>> + Send + 'a>>;

    fn execute_tool<'a>(
        &'a self,
        tool: ToolCall,
    ) -> Pin<Box<dyn Future<Output = anyhow::Result<ToolResult>> + Send + 'a>>;
}
