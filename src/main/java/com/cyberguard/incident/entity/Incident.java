package com.cyberguard.incident.entity;

import com.cyberguard.incident.enums.IncidentCategory;
import com.cyberguard.incident.enums.IncidentSeverity;
import com.cyberguard.incident.enums.IncidentStatus;
import jakarta.persistence.*;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.time.LocalDateTime;

@Entity
@Table(name = "incidents")
@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class Incident {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(nullable = false, length = 200)
    private String title;

    @Column(length = 1000)
    private String description;

    @Enumerated(EnumType.STRING)
    @Column(nullable = false, length = 40)
    private IncidentCategory category;

    // Set initially by the rule-based engine's simple heuristic;
    // may be overwritten later by the AI Risk Assessment agent (Week 3) with its reasoning.
    @Enumerated(EnumType.STRING)
    @Column(nullable = false, length = 20)
    private IncidentSeverity severity;

    @Enumerated(EnumType.STRING)
    @Builder.Default
    @Column(nullable = false, length = 30)
    private IncidentStatus status = IncidentStatus.OPEN;

    @Column(nullable = false, length = 100)
    private String affectedUsername;

    // The time window in which the triggering pattern was observed.
    @Column(nullable = false)
    private LocalDateTime windowStart;

    @Column(nullable = false)
    private LocalDateTime windowEnd;

    @Column(nullable = false)
    private int triggerEventCount;

    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "assigned_analyst_id")
    private User assignedAnalyst;

    // --- Fields populated later by the AI agent pipeline (Week 3) ---
    @Column(length = 100)
    private String aiClassification;

    @Column(length = 2000)
    private String aiRiskReasoning;

    @Column(length = 2000)
    private String aiRecommendation;

    @Column(columnDefinition = "TEXT")
    private String aiGeneratedReport;

    // "LLM:<model>", "PARTIAL_LLM:<model>" or "OFFLINE_RULES" - tells the analyst how the AI fields were produced.
    @Column(length = 60)
    private String aiAnalysisSource;

    private LocalDateTime aiAnalyzedAt;

    // Probability (0..1) that the trained ML model gives for this login pattern being an attack. Null = not scored.
    private Double mlScore;

    @Column(updatable = false)
    private LocalDateTime createdAt;

    private LocalDateTime updatedAt;

    @PrePersist
    protected void onCreate() {
        this.createdAt = LocalDateTime.now();
        this.updatedAt = this.createdAt;
    }

    @PreUpdate
    protected void onUpdate() {
        this.updatedAt = LocalDateTime.now();
    }
}
