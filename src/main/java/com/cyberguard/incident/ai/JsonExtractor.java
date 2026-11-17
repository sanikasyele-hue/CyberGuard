package com.cyberguard.incident.ai;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;

/**
 * LLMs sometimes wrap JSON in ```json fences or add a sentence before it.
 * This pulls out the first {...} block and parses it.
 */
public final class JsonExtractor {

    private static final ObjectMapper MAPPER = new ObjectMapper();

    private JsonExtractor() {
    }

    public static JsonNode parseObject(String llmText) {
        if (llmText == null) {
            throw new LlmException("Model returned no text");
        }
        int start = llmText.indexOf('{');
        int end = llmText.lastIndexOf('}');
        if (start < 0 || end <= start) {
            throw new LlmException("Model answer did not contain a JSON object");
        }
        try {
            JsonNode node = MAPPER.readTree(llmText.substring(start, end + 1));
            if (!node.isObject()) {
                throw new LlmException("Model answer was not a JSON object");
            }
            return node;
        } catch (LlmException e) {
            throw e;
        } catch (Exception e) {
            throw new LlmException("Model answer was not valid JSON", e);
        }
    }
}
