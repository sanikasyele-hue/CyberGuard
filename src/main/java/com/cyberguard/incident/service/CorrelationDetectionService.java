package com.cyberguard.incident.service;

import com.cyberguard.incident.detection.DetectionRules;
import com.cyberguard.incident.detection.Finding;
import com.cyberguard.incident.detection.LogEvent;
import com.cyberguard.incident.detection.SpraySubject;
import com.cyberguard.incident.entity.Incident;
import com.cyberguard.incident.entity.SecurityLog;
import com.cyberguard.incident.enums.EventType;
import com.cyberguard.incident.enums.IncidentCategory;
import com.cyberguard.incident.enums.IncidentSeverity;
import com.cyberguard.incident.enums.IncidentStatus;
import com.cyberguard.incident.enums.LogStatus;
import com.cyberguard.incident.event.IncidentCreatedEvent;
import com.cyberguard.incident.repository.IncidentRepository;
import com.cyberguard.incident.repository.SecurityLogRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.ApplicationEventPublisher;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.ArrayList;
import java.util.List;

/**
 * Detection rules 2 and 3 (rule 1, "too many failed logins", is in ThreatDetectionService).
 * The actual pattern matching is in DetectionRules (plain Java); this class only reads the logs
 * from the database and turns each finding into an Incident.
 *
 *   Rule 2  Brute force followed by a successful login  -> "possible account takeover"
 *   Rule 3  Password spray (one IP, many accounts)      -> "attacker is guessing across accounts"
 */
@Service
@RequiredArgsConstructor
public class CorrelationDetectionService {

    private final SecurityLogRepository securityLogRepository;
    private final IncidentRepository incidentRepository;
    private final ApplicationEventPublisher eventPublisher; // lets the AI agents react to new incidents

    @Value("${app.detection.failed-login-threshold}")
    private int failedLoginThreshold;

    @Value("${app.detection.window-minutes}")
    private int windowMinutes;

    @Value("${app.detection.compromise-min-failures:5}")
    private int compromiseMinFailures;

    @Value("${app.detection.spray-min-attempts:6}")
    private int sprayMinAttempts;

    @Value("${app.detection.spray-min-users:3}")
    private int sprayMinUsers;

    @Transactional
    public List<Incident> evaluateBruteForceThenSuccess(String username) {
        List<LogEvent> events = securityLogRepository
                .findByUsernameAndEventTypeOrderByEventTimestampAsc(username, EventType.LOGIN)
                .stream().map(CorrelationDetectionService::toEvent).toList();

        List<Incident> created = new ArrayList<>();
        for (Finding f : DetectionRules.bruteForceThenSuccess(events, compromiseMinFailures, windowMinutes)) {
            if (alreadyTracked(username, IncidentCategory.SUSPICIOUS_ACCESS_ACTIVITY, f)) {
                continue;
            }
            Incident incident = Incident.builder()
                    .title(truncate("Possible account takeover: successful login after " + f.failureCount()
                            + " failed attempts for user '" + username + "'", 200))
                    .description(truncate(String.format(
                            "User '%s' logged in successfully at %s, right after %d failed login attempts "
                                    + "(from %d IP address(es)) that started at %s. The password may have been guessed.",
                            username, f.windowEnd(), f.failureCount(), f.distinctIps(), f.windowStart()), 1000))
                    .category(IncidentCategory.SUSPICIOUS_ACCESS_ACTIVITY)
                    .severity(f.failureCount() >= failedLoginThreshold * 2
                            ? IncidentSeverity.CRITICAL : IncidentSeverity.HIGH)
                    .status(IncidentStatus.OPEN)
                    .affectedUsername(username)
                    .windowStart(f.windowStart())
                    .windowEnd(f.windowEnd())
                    .triggerEventCount(f.failureCount() + 1)
                    .build();
            created.add(saveAndAnnounce(incident));
        }
        return created;
    }

    @Transactional
    public List<Incident> evaluatePasswordSpray(String ip) {
        List<LogEvent> events = securityLogRepository
                .findBySourceIpAndEventTypeAndStatusOrderByEventTimestampAsc(ip, EventType.LOGIN, LogStatus.FAILED)
                .stream().map(CorrelationDetectionService::toEvent).toList();

        String subject = SpraySubject.of(ip);
        List<Incident> created = new ArrayList<>();
        for (Finding f : DetectionRules.passwordSpray(events, sprayMinAttempts, sprayMinUsers, windowMinutes)) {
            if (alreadyTracked(subject, IncidentCategory.AUTHENTICATION_ANOMALY, f)) {
                continue;
            }
            List<String> shown = f.users().size() > 10 ? f.users().subList(0, 10) : f.users();
            Incident incident = Incident.builder()
                    .title(truncate("Password spray from IP " + ip + " against " + f.distinctUsers() + " accounts", 200))
                    .description(truncate(String.format(
                            "IP %s made %d failed login attempts against %d different accounts between %s and %s. "
                                    + "Accounts: %s%s.",
                            ip, f.failureCount(), f.distinctUsers(), f.windowStart(), f.windowEnd(),
                            String.join(", ", shown), f.users().size() > 10 ? ", ..." : ""), 1000))
                    .category(IncidentCategory.AUTHENTICATION_ANOMALY)
                    .severity(f.distinctUsers() >= 10 ? IncidentSeverity.CRITICAL : IncidentSeverity.HIGH)
                    .status(IncidentStatus.OPEN)
                    .affectedUsername(subject)
                    .windowStart(f.windowStart())
                    .windowEnd(f.windowEnd())
                    .triggerEventCount(f.failureCount())
                    .build();
            created.add(saveAndAnnounce(incident));
        }
        return created;
    }

    private boolean alreadyTracked(String subject, IncidentCategory category, Finding f) {
        return !incidentRepository
                .findOverlappingOpenIncidents(subject, category, f.windowStart(), f.windowEnd())
                .isEmpty();
    }

    private Incident saveAndAnnounce(Incident incident) {
        Incident saved = incidentRepository.save(incident);
        eventPublisher.publishEvent(new IncidentCreatedEvent(saved.getId()));
        return saved;
    }

    private static LogEvent toEvent(SecurityLog l) {
        return new LogEvent(l.getEventTimestamp(), l.getUsername(), l.getSourceIp(), l.getStatus() == LogStatus.FAILED);
    }

    private static String truncate(String s, int max) {
        return s.length() <= max ? s : s.substring(0, max);
    }
}
