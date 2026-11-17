package com.cyberguard.incident.ai;

/**
 * The ONLY thing the 3 agents know about the outside AI world.
 *
 * To switch to another provider (Azure OpenAI, Ollama, Groq, a mock for tests...),
 * write another class that implements this interface - no agent code changes.
 */
public interface LlmClient {

    /** true when an API key is present, so real LLM calls can be made. */
    boolean isConfigured();

    /** Model name, only used to label results (e.g. "gpt-4o-mini"). */
    String modelName();

    /**
     * Sends one system prompt + one user prompt, returns the model's text answer.
     *
     * @throws LlmException on network errors, non-2xx responses or empty answers
     */
    String complete(String systemPrompt, String userPrompt);
}
