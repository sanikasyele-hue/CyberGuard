package com.cyberguard.incident.ai;

import com.cyberguard.incident.enums.IncidentCategory;
import com.cyberguard.incident.enums.IncidentSeverity;

import java.time.LocalDateTime;
import java.util.List;

/**
 * Everything the agents are allowed to know about one incident.
 * It is a plain Java object (no database classes), so the agents are easy to test.
 *
 * SECURITY: log files are attacker-controlled (a username could literally be
 * "ignore previous instructions..."). So every text field is cleaned here:
 * control characters and angle brackets removed, length limited.
 * The prompts also tell the model to treat evidence as data, never as instructions.
 */
public record AnalysisContext(
        Long incidentId,
        String title,
        String description,
        String affectedUsername,
        LocalDateTime windowStart,
        LocalDateTime windowEnd,
        int triggerEventCount,
        IncidentCategory ruleCategory,
        IncidentSeverity ruleSeverity,
        List<String> evidence,
        int distinctSourceIps,
        int distinctTargetedUsers,
        boolean successAfterFailures,
        Double mlAttackProbability
) {
    private static final int MAX_EVIDENCE_LINES = 40;

    public AnalysisContext {
        title = clean(title, 200);
        description = clean(description, 500);
        affectedUsername = clean(affectedUsername, 100);
        evidence = evidence == null ? List.of()
                : evidence.stream().limit(MAX_EVIDENCE_LINES).map(l -> clean(l, 200)).toList();
    }

    /** "93%" or "not available" - for prompts and reports. */
    public String mlText() {
        return mlAttackProbability == null ? "not available" : Math.round(mlAttackProbability * 100) + "%";
    }

    /** Evidence as numbered lines for prompts. */
    public String evidenceBlock() {
        if (evidence.isEmpty()) {
            return "(no log lines available)";
        }
        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < evidence.size(); i++) {
            sb.append(i + 1).append(". ").append(evidence.get(i)).append('\n');
        }
        return sb.toString().trim();
    }

    /** Removes control characters and < > , collapses spaces, cuts to maxLen. */
    public static String clean(String text, int maxLen) {
        if (text == null) {
            return "";
        }
        String s = text.replaceAll("[\\p{Cntrl}<>]", " ").replaceAll("\\s+", " ").trim();
        return s.length() <= maxLen ? s : s.substring(0, maxLen);
    }
}
