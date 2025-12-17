use crate::advisor_todos_backend::AdviceTypeBackend;
use blake3::Hasher;
use serde::{Deserialize, Serialize};

// =============================================================================
// LLM Provider Backend - Request/Response structures for Backend LLM proxy
// =============================================================================
//
// These structures are used when LLMProvider::Backend is configured in llm_client.rs.
// The client constructs the prompt (same as for Claude/OpenAI) and sends it to
// the backend, which forwards it to its internal LLM provider and returns the response.
//
// This allows centralized LLM management where the backend owns the API keys
// and LLM configuration, while clients send pre-constructed prompts.
// =============================================================================

// =============================================================================
// Analysis Request Backend - Sent from LLMProvider::Backend to the backend
// =============================================================================

/// Request for agentic analysis via Backend LLM proxy
///
/// The client constructs the prompt (same logic as for Claude/OpenAI) and sends
/// it to the backend. The backend forwards it to its internal LLM provider.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AgenticAnalysisRequestBackend {
    /// The pre-constructed prompt to send to the LLM
    pub prompt: String,
    /// The system prompt to send to the LLM
    pub system_prompt: String,
    /// Maximum tokens for the response
    pub max_tokens: u32,
    /// Type of analysis to perform
    pub analysis_type: AdviceTypeBackend,
}

impl AgenticAnalysisRequestBackend {
    pub fn uid(&self) -> String {
        let mut hasher = Hasher::new();
        hasher.update(self.prompt.as_bytes());
        hasher.update(self.max_tokens.to_le_bytes().as_slice());
        hasher.finalize().to_hex().to_string()
    }
}

// =============================================================================
// Decision Backend - LLM's decision (extracted from tool call response)
// =============================================================================

/// LLM's decision about a todo - Raw string response from backend LLM
/// The backend returns the raw LLM response which needs to be parsed like Claude/OpenAI
pub type AgenticDecisionBackend = String;

// =============================================================================
// Analysis Response Backend - Returned from the backend
// =============================================================================

/// Response from agentic analysis via Backend LLM proxy
///
/// The backend returns the raw LLM response (text completion) that needs to be parsed
/// for the make_decision tool call, similar to Claude/OpenAI responses.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AgenticAnalysisResponseBackend {
    /// The raw LLM response text (needs parsing for tool call)
    pub response_text: String,
    /// Input tokens consumed
    pub input_tokens: u32,
    /// Output tokens generated
    pub output_tokens: u32,
}

impl AgenticAnalysisResponseBackend {
    pub fn uid(&self) -> String {
        let mut hasher = Hasher::new();
        hasher.update(self.response_text.as_bytes());
        hasher.update(self.input_tokens.to_le_bytes().as_slice());
        hasher.update(self.output_tokens.to_le_bytes().as_slice());
        hasher.finalize().to_hex().to_string()
    }
}
