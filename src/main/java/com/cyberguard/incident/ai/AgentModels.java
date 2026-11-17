package com.cyberguard.incident.ai;

import com.cyberguard.incident.enums.IncidentCategory;
import com.cyberguard.incident.enums.IncidentSeverity;

import java.util.List;

/** Small result objects passed from one agent to the next. */
public final class AgentModels {

    private AgentModels() {
    }

    /** Where an answer came from. OFFLINE_RULES = built-in fallback, no LLM was used. */
    public enum Source {
        LLM, OFFLINE_RULES
    }

    /** Output of Agent 1. */
    public record Classification(IncidentCategory category, int confidence, String summary, Source source) {
    }

    /** Output of Agent 2. */
    public record Risk(IncidentSeverity level, String reasoning, Source source) {
    }

    /** Output of Agent 3. */
    public record Response(List<String> actions, String report, Source source) {
    }

    /** Output of the whole chain. */
    public record PipelineResult(Classification classification, Risk risk, Response response) {

        /** "LLM:gpt-4o-mini", "OFFLINE_RULES" or "PARTIAL_LLM:gpt-4o-mini". */
        public String sourceLabel(String modelName) {
            int llmCount = 0;
            if (classification.source() == Source.LLM) llmCount++;
            if (risk.source() == Source.LLM) llmCount++;
            if (response.source() == Source.LLM) llmCount++;
            if (llmCount == 3) return "LLM:" + modelName;
            if (llmCount == 0) return "OFFLINE_RULES";
            return "PARTIAL_LLM:" + modelName;
        }
    }
}
