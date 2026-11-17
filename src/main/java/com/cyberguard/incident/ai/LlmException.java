package com.cyberguard.incident.ai;

/** Thrown when the LLM call fails or returns something we cannot use. Agents catch this and fall back. */
public class LlmException extends RuntimeException {
    public LlmException(String message) {
        super(message);
    }

    public LlmException(String message, Throwable cause) {
        super(message, cause);
    }
}
