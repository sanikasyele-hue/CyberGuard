package com.cyberguard.incident.service;

import com.cyberguard.incident.entity.Incident;
import com.cyberguard.incident.entity.SecurityLog;
import com.cyberguard.incident.enums.EventType;
import com.cyberguard.incident.enums.IncidentCategory;
import com.cyberguard.incident.enums.IncidentSeverity;
import com.cyberguard.incident.enums.IncidentStatus;
import com.cyberguard.incident.enums.LogStatus;
import com.cyberguard.incident.repository.IncidentRepository;
import com.cyberguard.incident.repository.SecurityLogRepository;
import lombok.RequiredArgsConstructor;
import com.cyberguard.incident.event.IncidentCreatedEvent;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.ApplicationEventPublisher;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.Duration;
import java.time.LocalDateTime;
import java.util.ArrayList;
import java.util.List;

/**
 * Rule-based detection: scans a user's failed-login history for any
 * windowMinutes-wide period containing at least failedLoginThreshold events.
 *
 * This is intentionally simple and deterministic (no AI here) — the AI agent
 * pipeline (Week 3) later reads the incidents this creates and adds
 * classification, nuanced risk reasoning, and recommended actions on top.
 */
@Service
@RequiredArgsConstructor
public class ThreatDetectionService {

    private final SecurityLogRepository securityLogRepository;
    private final IncidentRepository incidentRepository;
    private final ApplicationEventPublisher eventPublisher; // lets the AI agents react to new incidents

    @Value("${app.detection.failed-login-threshold}")
    private int failedLoginThreshold;

    @Value("${app.detection.window-minutes}")
    private int windowMinutes;

    @Transactional
    public List<Incident> evaluateUser(String username) {
        List<SecurityLog> failedLogins = securityLogRepository
                .findByUsernameAndEventTypeAndStatusOrderByEventTimestampAsc(
                        username, EventType.LOGIN, LogStatus.FAILED);

        List<Incident> createdIncidents = new ArrayList<>();

        int i = 0;
        while (i < failedLogins.size()) {
            LocalDateTime anchor = failedLogins.get(i).getEventTimestamp();

            // Expand j as far as possible while staying within windowMinutes of the anchor.
            int j = i;
            while (j + 1 < failedLogins.size()
                    && Duration.between(anchor, failedLogins.get(j + 1).getEventTimestamp()).toMinutes() <= windowMinutes) {
                j++;
            }

            int count = j - i + 1;

            if (count >= failedLoginThreshold) {
                LocalDateTime windowStart = anchor;
                LocalDateTime windowEnd = failedLogins.get(j).getEventTimestamp();

                boolean alreadyTracked = !incidentRepository.findOverlappingOpenIncidents(
                        username, IncidentCategory.AUTHENTICATION_ANOMALY, windowStart, windowEnd
                ).isEmpty();

                if (!alreadyTracked) {
                    Incident incident = buildIncident(username, windowStart, windowEnd, count);
                    Incident saved = incidentRepository.save(incident);
                    createdIncidents.add(saved);
                    eventPublisher.publishEvent(new IncidentCreatedEvent(saved.getId()));
                }

                // Skip past this window — the events inside it are already accounted for,
                // so we don't want overlapping incidents from the same scan.
                i = j + 1;
            } else {
                i++;
            }
        }

        return createdIncidents;
    }

    private Incident buildIncident(String username, LocalDateTime windowStart, LocalDateTime windowEnd, int count) {
        return Incident.builder()
                .title("Multiple failed login attempts detected for user '" + username + "'")
                .description(String.format(
                        "%d failed login attempts detected for user '%s' between %s and %s (threshold: %d within %d minutes).",
                        count, username, windowStart, windowEnd, failedLoginThreshold, windowMinutes))
                .category(IncidentCategory.AUTHENTICATION_ANOMALY)
                .severity(computeSeverity(count))
                .status(IncidentStatus.OPEN)
                .affectedUsername(username)
                .windowStart(windowStart)
                .windowEnd(windowEnd)
                .triggerEventCount(count)
                .build();
    }

    /**
     * Severity scales with how far past the threshold the count is, so the
     * bands move sensibly even if failedLoginThreshold is reconfigured.
     */
    private IncidentSeverity computeSeverity(int count) {
        if (count >= failedLoginThreshold * 4) {
            return IncidentSeverity.CRITICAL;
        } else if (count >= failedLoginThreshold * 2) {
            return IncidentSeverity.HIGH;
        } else {
            return IncidentSeverity.MEDIUM;
        }
    }
}
