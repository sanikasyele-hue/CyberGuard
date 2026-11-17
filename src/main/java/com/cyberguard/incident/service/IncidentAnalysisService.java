package com.cyberguard.incident.service;

import com.cyberguard.incident.ai.AgentModels.PipelineResult;
import com.cyberguard.incident.ai.AgentPipeline;
import com.cyberguard.incident.ai.AnalysisContext;
import com.cyberguard.incident.ai.LlmClient;
import com.cyberguard.incident.detection.LogEvent;
import com.cyberguard.incident.detection.SpraySubject;
import com.cyberguard.incident.ml.MlModelService;
import com.cyberguard.incident.entity.Incident;
import com.cyberguard.incident.entity.SecurityLog;
import com.cyberguard.incident.enums.EventType;
import com.cyberguard.incident.enums.LogStatus;
import com.cyberguard.incident.exception.DuplicateResourceException;
import com.cyberguard.incident.exception.ResourceNotFoundException;
import com.cyberguard.incident.repository.IncidentRepository;
import com.cyberguard.incident.repository.SecurityLogRepository;
import org.springframework.stereotype.Service;

import java.time.LocalDateTime;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;

/**
 * Glue between the database and the 3-agent pipeline:
 *   load incident + evidence logs  ->  run agents  ->  save results on the incident.
 *
 * Deliberately NOT @Transactional: the LLM calls take seconds and we must not
 * hold a database transaction open while waiting for them.
 */
@Service
public class IncidentAnalysisService {

    private static final int EVIDENCE_BEFORE_MINUTES = 5;
    private static final int EVIDENCE_AFTER_MINUTES = 30; // to catch a successful login AFTER the failures

    private final IncidentRepository incidentRepository;
    private final SecurityLogRepository securityLogRepository;
    private final AgentPipeline pipeline;
    private final LlmClient llmClient;
    private final MlModelService mlModelService;

    // Prevents two analyses of the same incident running at once (double-click, upload + manual).
    private final Set<Long> inFlight = ConcurrentHashMap.newKeySet();

    public IncidentAnalysisService(IncidentRepository incidentRepository,
                                   SecurityLogRepository securityLogRepository,
                                   AgentPipeline pipeline,
                                   LlmClient llmClient,
                                   MlModelService mlModelService) {
        this.incidentRepository = incidentRepository;
        this.securityLogRepository = securityLogRepository;
        this.pipeline = pipeline;
        this.llmClient = llmClient;
        this.mlModelService = mlModelService;
    }

    public Incident analyze(Long incidentId) {
        if (!inFlight.add(incidentId)) {
            throw new DuplicateResourceException("AI analysis is already running for incident " + incidentId);
        }
        try {
            Incident incident = incidentRepository.findById(incidentId)
                    .orElseThrow(() -> new ResourceNotFoundException("Incident not found: " + incidentId));

            Double mlScore = computeMlScore(incident);
            AnalysisContext context = buildContext(incident, mlScore);
            PipelineResult result = pipeline.run(context);
            return saveResult(incidentId, result, mlScore);
        } finally {
            inFlight.remove(incidentId);
        }
    }

    /** Asks the trained ML model how likely this user's login pattern is an attack. Null when not applicable. */
    private Double computeMlScore(Incident incident) {
        String subject = incident.getAffectedUsername();
        if (!mlModelService.isReady() || SpraySubject.isSpray(subject)) {
            return null; // spray incidents are about an IP, the model scores one user's logins
        }
        List<LogEvent> events = securityLogRepository
                .findByUsernameAndEventTimestampBetweenOrderByEventTimestampAsc(
                        subject, incident.getWindowStart(), incident.getWindowEnd().plusMinutes(5))
                .stream()
                .filter(l -> l.getEventType() == EventType.LOGIN)
                .map(l -> new LogEvent(l.getEventTimestamp(), l.getUsername(), l.getSourceIp(),
                        l.getStatus() == LogStatus.FAILED))
                .toList();
        return events.isEmpty() ? null : mlModelService.probability(events);
    }

    private AnalysisContext buildContext(Incident incident, Double mlScore) {
        String subject = incident.getAffectedUsername();
        boolean sprayIncident = SpraySubject.isSpray(subject); // incident is about an attacker IP, not one user
        LocalDateTime from = incident.getWindowStart().minusMinutes(EVIDENCE_BEFORE_MINUTES);
        LocalDateTime to = incident.getWindowEnd().plusMinutes(EVIDENCE_AFTER_MINUTES);

        List<SecurityLog> logs = sprayIncident
                ? securityLogRepository.findBySourceIpAndEventTimestampBetweenOrderByEventTimestampAsc(
                        SpraySubject.ipOf(subject), from, to)
                : securityLogRepository.findByUsernameAndEventTimestampBetweenOrderByEventTimestampAsc(
                        subject, from, to);

        List<String> evidence = new ArrayList<>();
        Set<String> failedIps = new HashSet<>();
        Set<String> failedUsers = new HashSet<>();
        LocalDateTime firstFailure = null;
        LocalDateTime lastFailure = null;

        for (SecurityLog l : logs) {
            evidence.add(String.format("%s %s %s user=%s ip=%s", l.getEventTimestamp(), l.getEventType(),
                    l.getStatus(), l.getUsername(), l.getSourceIp() == null ? "unknown" : l.getSourceIp()));

            boolean failedLoginInWindow = l.getEventType() == EventType.LOGIN
                    && l.getStatus() == LogStatus.FAILED
                    && !l.getEventTimestamp().isBefore(incident.getWindowStart())
                    && !l.getEventTimestamp().isAfter(incident.getWindowEnd());
            if (failedLoginInWindow) {
                LocalDateTime t = l.getEventTimestamp();
                if (firstFailure == null || t.isBefore(firstFailure)) {
                    firstFailure = t;
                }
                if (lastFailure == null || t.isAfter(lastFailure)) {
                    lastFailure = t;
                }
                failedUsers.add(l.getUsername());
                if (l.getSourceIp() != null) {
                    failedIps.add(l.getSourceIp());
                }
            }
        }

        // One user: a success AFTER the last failure. One attacker IP: any success from it after the first failure.
        LocalDateTime reference = sprayIncident ? firstFailure : lastFailure;
        boolean successAfterFailures = false;
        if (reference != null) {
            for (SecurityLog l : logs) {
                if (l.getEventType() == EventType.LOGIN && l.getStatus() == LogStatus.SUCCESS
                        && l.getEventTimestamp().isAfter(reference)) {
                    successAfterFailures = true;
                    break;
                }
            }
        }

        return new AnalysisContext(
                incident.getId(), incident.getTitle(), incident.getDescription(),
                subject, incident.getWindowStart(), incident.getWindowEnd(),
                incident.getTriggerEventCount(), incident.getCategory(), incident.getSeverity(),
                evidence, failedIps.size(), failedUsers.size(), successAfterFailures, mlScore);
    }

    private Incident saveResult(Long incidentId, PipelineResult result, Double mlScore) {
        // Re-load so we only touch the AI fields and never overwrite a status change
        // an analyst made while the agents were thinking.
        Incident fresh = incidentRepository.findById(incidentId)
                .orElseThrow(() -> new ResourceNotFoundException("Incident not found: " + incidentId));

        fresh.setAiClassification(truncate(
                result.classification().category() + " (confidence " + result.classification().confidence() + "%)", 100));
        fresh.setSeverity(result.risk().level());
        fresh.setAiRiskReasoning(truncate(result.risk().reasoning(), 2000));
        fresh.setAiRecommendation(truncate(numbered(result.response().actions()), 2000));
        fresh.setAiGeneratedReport(result.response().report());
        fresh.setAiAnalysisSource(truncate(result.sourceLabel(llmClient.modelName()), 60));
        fresh.setAiAnalyzedAt(LocalDateTime.now());
        fresh.setMlScore(mlScore);

        // NOTE: incident.category is left as the rule engine set it, because the
        // duplicate-incident check in ThreatDetectionService relies on it.
        return incidentRepository.save(fresh);
    }

    private static String numbered(List<String> items) {
        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < items.size(); i++) {
            sb.append(i + 1).append(". ").append(items.get(i)).append('\n');
        }
        return sb.toString().trim();
    }

    private static String truncate(String s, int max) {
        return s.length() <= max ? s : s.substring(0, max);
    }
}
