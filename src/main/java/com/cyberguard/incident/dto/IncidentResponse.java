package com.cyberguard.incident.dto;

import com.cyberguard.incident.entity.Incident;
import com.cyberguard.incident.enums.IncidentCategory;
import com.cyberguard.incident.enums.IncidentSeverity;
import com.cyberguard.incident.enums.IncidentStatus;
import lombok.Builder;
import lombok.Data;

import java.time.LocalDateTime;

@Data
@Builder
public class IncidentResponse {
    private Long id;
    private String title;
    private String description;
    private IncidentCategory category;
    private IncidentSeverity severity;
    private IncidentStatus status;
    private String affectedUsername;
    private LocalDateTime windowStart;
    private LocalDateTime windowEnd;
    private int triggerEventCount;
    private String assignedAnalystUsername;
    private String aiClassification;
    private String aiRiskReasoning;
    private String aiRecommendation;
    private String aiGeneratedReport;
    private String aiAnalysisSource;
    private LocalDateTime aiAnalyzedAt;
    private Double mlScore;
    private LocalDateTime createdAt;
    private LocalDateTime updatedAt;

    public static IncidentResponse from(Incident incident) {
        return IncidentResponse.builder()
                .id(incident.getId())
                .title(incident.getTitle())
                .description(incident.getDescription())
                .category(incident.getCategory())
                .severity(incident.getSeverity())
                .status(incident.getStatus())
                .affectedUsername(incident.getAffectedUsername())
                .windowStart(incident.getWindowStart())
                .windowEnd(incident.getWindowEnd())
                .triggerEventCount(incident.getTriggerEventCount())
                .assignedAnalystUsername(
                        incident.getAssignedAnalyst() != null ? incident.getAssignedAnalyst().getUsername() : null)
                .aiClassification(incident.getAiClassification())
                .aiRiskReasoning(incident.getAiRiskReasoning())
                .aiRecommendation(incident.getAiRecommendation())
                .aiGeneratedReport(incident.getAiGeneratedReport())
                .aiAnalysisSource(incident.getAiAnalysisSource())
                .aiAnalyzedAt(incident.getAiAnalyzedAt())
                .mlScore(incident.getMlScore())
                .createdAt(incident.getCreatedAt())
                .updatedAt(incident.getUpdatedAt())
                .build();
    }
}
