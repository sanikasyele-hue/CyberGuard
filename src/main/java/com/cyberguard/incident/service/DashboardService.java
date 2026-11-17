package com.cyberguard.incident.service;

import com.cyberguard.incident.dashboard.DashboardCalculator;
import com.cyberguard.incident.dashboard.DashboardSummary;
import com.cyberguard.incident.dashboard.FailedLoginRow;
import com.cyberguard.incident.dashboard.IncidentRow;
import com.cyberguard.incident.enums.EventType;
import com.cyberguard.incident.enums.LogStatus;
import com.cyberguard.incident.repository.IncidentRepository;
import com.cyberguard.incident.repository.SecurityLogRepository;
import org.springframework.stereotype.Service;

import java.util.List;

/**
 * Reads the data and hands it to DashboardCalculator (which does the counting).
 * It loads incidents and failed logins into memory, which is fine for a project of this size;
 * for millions of rows replace it with GROUP BY queries.
 */
@Service
public class DashboardService {

    private final IncidentRepository incidentRepository;
    private final SecurityLogRepository securityLogRepository;

    public DashboardService(IncidentRepository incidentRepository, SecurityLogRepository securityLogRepository) {
        this.incidentRepository = incidentRepository;
        this.securityLogRepository = securityLogRepository;
    }

    public DashboardSummary summary() {
        List<IncidentRow> incidents = incidentRepository.findAll().stream()
                .map(i -> new IncidentRow(i.getId(), i.getTitle(), i.getSeverity(), i.getStatus(), i.getCategory(),
                        i.getAffectedUsername(), i.getWindowStart(), i.getAiAnalyzedAt() != null))
                .toList();

        List<FailedLoginRow> failedLogins = securityLogRepository
                .findByEventTypeAndStatusAndSourceIpIsNotNull(EventType.LOGIN, LogStatus.FAILED).stream()
                .map(l -> new FailedLoginRow(l.getSourceIp(), l.getUsername()))
                .toList();

        return DashboardCalculator.build(
                incidents,
                securityLogRepository.count(),
                securityLogRepository.countByEventTypeAndStatus(EventType.LOGIN, LogStatus.FAILED),
                failedLogins);
    }
}
