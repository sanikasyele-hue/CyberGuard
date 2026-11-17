package com.cyberguard.incident.detection;

import java.time.LocalDateTime;

/** One LOGIN attempt, reduced to what the detection rules need. Plain Java, easy to test. */
public record LogEvent(LocalDateTime time, String username, String sourceIp, boolean failed) {
}
