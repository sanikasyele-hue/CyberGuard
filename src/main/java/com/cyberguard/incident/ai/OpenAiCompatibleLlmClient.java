package com.cyberguard.incident.ai;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ArrayNode;
import com.fasterxml.jackson.databind.node.ObjectNode;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import java.io.IOException;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.time.Duration;

/**
 * Talks to any OpenAI-compatible "chat completions" API
 * (OpenAI, Azure OpenAI-compatible gateways, Groq, Ollama, LM Studio, ...).
 * Uses only the JDK's built-in HttpClient + Jackson, so there is no extra library to install.
 */
@Component
public class OpenAiCompatibleLlmClient implements LlmClient {

    private static final Logger log = LoggerFactory.getLogger(OpenAiCompatibleLlmClient.class);

    private final ObjectMapper mapper = new ObjectMapper();
    private final HttpClient http = HttpClient.newBuilder()
            .connectTimeout(Duration.ofSeconds(10))
            .build(); // redirects are NOT followed, so the API key can never be forwarded elsewhere

    private final String apiKey;
    private final String endpoint;
    private final String model;
    private final int maxTokens;
    private final Duration requestTimeout;

    public OpenAiCompatibleLlmClient(
            @Value("${app.ai.provider-api-key:}") String apiKey,
            @Value("${app.ai.base-url:https://api.openai.com/v1}") String baseUrl,
            @Value("${app.ai.model:gpt-4o-mini}") String model,
            @Value("${app.ai.timeout-seconds:30}") int timeoutSeconds,
            @Value("${app.ai.max-tokens:900}") int maxTokens
    ) {
        this.apiKey = apiKey == null ? "" : apiKey.trim();
        String base = baseUrl == null ? "" : baseUrl.trim();
        while (base.endsWith("/")) {
            base = base.substring(0, base.length() - 1);
        }
        this.endpoint = base + "/chat/completions";
        this.model = model;
        this.maxTokens = maxTokens;
        this.requestTimeout = Duration.ofSeconds(timeoutSeconds);
    }

    @Override
    public boolean isConfigured() {
        // Treat the placeholder text from .env.example / run scripts as "not configured".
        return !apiKey.isBlank()
                && !apiKey.startsWith("your_")
                && !apiKey.contains("PASTE");
    }

    @Override
    public String modelName() {
        return model;
    }

    @Override
    public String complete(String systemPrompt, String userPrompt) {
        if (!isConfigured()) {
            throw new LlmException("AI_PROVIDER_API_KEY is not set");
        }

        try {
            ObjectNode body = mapper.createObjectNode();
            body.put("model", model);
            body.put("temperature", 0.2);
            body.put("max_tokens", maxTokens);
            ArrayNode messages = body.putArray("messages");
            messages.addObject().put("role", "system").put("content", systemPrompt);
            messages.addObject().put("role", "user").put("content", userPrompt);

            HttpRequest request = HttpRequest.newBuilder(URI.create(endpoint))
                    .timeout(requestTimeout)
                    .header("Authorization", "Bearer " + apiKey)
                    .header("Content-Type", "application/json")
                    .POST(HttpRequest.BodyPublishers.ofString(mapper.writeValueAsString(body)))
                    .build();

            HttpResponse<String> response = http.send(request, HttpResponse.BodyHandlers.ofString());
            JsonNode root = parseQuietly(response.body());

            if (response.statusCode() < 200 || response.statusCode() >= 300) {
                // Log only the provider's short error message - never the request, never the key.
                String reason = root.path("error").path("message").asText("no details");
                throw new LlmException("LLM API returned HTTP " + response.statusCode() + ": " + shorten(reason));
            }

            String content = root.path("choices").path(0).path("message").path("content").asText("");
            if (content.isBlank()) {
                throw new LlmException("LLM API returned an empty answer");
            }
            return content;

        } catch (IOException e) {
            throw new LlmException("LLM request failed: " + e.getClass().getSimpleName(), e);
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            throw new LlmException("LLM request was interrupted", e);
        } catch (IllegalArgumentException e) {
            // thrown by URI.create when AI_PROVIDER_BASE_URL is malformed
            throw new LlmException("AI_PROVIDER_BASE_URL is not a valid URL", e);
        }
    }

    private JsonNode parseQuietly(String text) {
        try {
            return mapper.readTree(text == null ? "" : text);
        } catch (IOException e) {
            return mapper.createObjectNode();
        }
    }

    private static String shorten(String s) {
        return s.length() <= 200 ? s : s.substring(0, 200) + "...";
    }
}
