package com.cyberguard.incident.dashboard;

import com.cyberguard.incident.enums.IncidentCategory;
import com.cyberguard.incident.enums.IncidentSeverity;
import com.cyberguard.incident.enums.IncidentStatus;

import java.time.LocalDateTime;

/** The few incident fields the dashboard needs (plain Java so the maths can be unit-tested). */
public record IncidentRow(
        Long id,
        String title,
        IncidentSeverity severity,
        IncidentStatus status,
        IncidentCategory category,
        String subject,
        LocalDateTime windowStart,
        boolean aiAnalysed
) {
}
