package com.cyberguard.incident.service;

import com.cyberguard.incident.detection.LogEvent;
import com.cyberguard.incident.entity.Incident;
import com.cyberguard.incident.entity.SecurityLog;
import com.cyberguard.incident.enums.EventType;
import com.cyberguard.incident.enums.IncidentCategory;
import com.cyberguard.incident.enums.IncidentSeverity;
import com.cyberguard.incident.enums.IncidentStatus;
import com.cyberguard.incident.enums.LogStatus;
import com.cyberguard.incident.event.IncidentCreatedEvent;
import com.cyberguard.incident.ml.MlFinding;
import com.cyberguard.incident.ml.MlModelService;
import com.cyberguard.incident.repository.IncidentRepository;
import com.cyberguard.incident.repository.SecurityLogRepository;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.ApplicationEventPublisher;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.ArrayList;
import java.util.List;

/**
 * Machine-learning detection. After the fixed rules have run, the trained model looks at the
 * login history of a user. Any time range it rates as an attack (probability above the threshold)
 * that is NOT already covered by an incident becomes a new incident.
 */
@Service
public class MlDetectionService {

    private final SecurityLogRepository securityLogRepository;
    private final IncidentRepository incidentRepository;
    private final MlModelService mlModelService;
    private final ApplicationEventPublisher eventPublisher;
    private final int windowMinutes;

    public MlDetectionService(SecurityLogRepository securityLogRepository,
                              IncidentRepository incidentRepository,
                              MlModelService mlModelService,
                              ApplicationEventPublisher eventPublisher,
                              @Value("${app.detection.window-minutes}") int windowMinutes) {
        this.securityLogRepository = securityLogRepository;
        this.incidentRepository = incidentRepository;
        this.mlModelService = mlModelService;
        this.eventPublisher = eventPublisher;
        this.windowMinutes = windowMinutes;
    }

    @Transactional
    public List<Incident> evaluateUser(String username) {
        List<Incident> created = new ArrayList<>();
        if (!mlModelService.isReady()) {
            return created;
        }

        List<LogEvent> events = securityLogRepository
                .findByUsernameAndEventTypeOrderByEventTimestampAsc(username, EventType.LOGIN)
                .stream().map(MlDetectionService::toEvent).toList();

        for (MlFinding f : mlModelService.findRanges(events, windowMinutes)) {
            boolean alreadyCovered = !incidentRepository
                    .findByAffectedUsernameAndStatusNotAndWindowStartLessThanEqualAndWindowEndGreaterThanEqual(
                            username, IncidentStatus.CLOSED, f.end(), f.start())
                    .isEmpty();
            if (alreadyCovered) {
                continue;
            }

            long percent = Math.round(f.probability() * 100);
            Incident incident = Incident.builder()
                    .title(truncate("ML-detected suspicious logins for user '" + username + "' (" + percent
                            + "% attack probability)", 200))
                    .description(truncate(String.format(
                            "The trained model rated the login pattern of user '%s' between %s and %s as %d%% likely "
                                    + "to be an attack (%d login events, %d failed%s). No existing incident covered this time range.",
                            username, f.start(), f.end(), percent, f.eventCount(), f.failures(),
                            f.successAfterFailure() ? ", followed by a successful login" : ""), 1000))
                    .category(f.successAfterFailure()
                            ? IncidentCategory.SUSPICIOUS_ACCESS_ACTIVITY : IncidentCategory.AUTHENTICATION_ANOMALY)
                    .severity(f.probability() >= 0.95 ? IncidentSeverity.HIGH : IncidentSeverity.MEDIUM)
                    .status(IncidentStatus.OPEN)
                    .affectedUsername(username)
                    .windowStart(f.start())
                    .windowEnd(f.end())
                    .triggerEventCount(f.eventCount())
                    .mlScore(f.probability())
                    .build();

            Incident saved = incidentRepository.save(incident);
            created.add(saved);
            eventPublisher.publishEvent(new IncidentCreatedEvent(saved.getId()));
        }
        return created;
    }

    private static LogEvent toEvent(SecurityLog l) {
        return new LogEvent(l.getEventTimestamp(), l.getUsername(), l.getSourceIp(), l.getStatus() == LogStatus.FAILED);
    }

    private static String truncate(String s, int max) {
        return s.length() <= max ? s : s.substring(0, max);
    }
}
