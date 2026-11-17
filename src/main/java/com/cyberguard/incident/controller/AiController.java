package com.cyberguard.incident.controller;

import com.cyberguard.incident.ai.LlmClient;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.LinkedHashMap;
import java.util.Map;

@RestController
@RequestMapping("/api/ai")
public class AiController {

    private final LlmClient llmClient;
    private final boolean autoAnalyze;

    public AiController(LlmClient llmClient, @Value("${app.ai.auto-analyze:true}") boolean autoAnalyze) {
        this.llmClient = llmClient;
        this.autoAnalyze = autoAnalyze;
    }

    /** Tells the UI whether real LLM calls are possible or the offline fallback will be used. */
    @GetMapping("/status")
    public ResponseEntity<Map<String, Object>> status() {
        boolean configured = llmClient.isConfigured();
        Map<String, Object> body = new LinkedHashMap<>();
        body.put("llmConfigured", configured);
        body.put("mode", configured ? "LLM" : "OFFLINE_RULES");
        body.put("model", llmClient.modelName());
        body.put("autoAnalyze", autoAnalyze);
        return ResponseEntity.ok(body);
    }
}
