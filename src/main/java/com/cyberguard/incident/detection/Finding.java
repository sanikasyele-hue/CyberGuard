package com.cyberguard.incident.detection;

import java.time.LocalDateTime;
import java.util.List;

/** A pattern a rule found. The detection service turns it into an Incident. */
public record Finding(
        LocalDateTime windowStart,
        LocalDateTime windowEnd,
        int failureCount,
        int distinctUsers,
        int distinctIps,
        List<String> users
) {
}
