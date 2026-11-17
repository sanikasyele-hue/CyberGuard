package com.cyberguard.incident.ml;

import java.time.LocalDateTime;

/** A time range of one user's logins that the model rates as suspicious. */
public record MlFinding(LocalDateTime start, LocalDateTime end, double probability,
                        int eventCount, int failures, boolean successAfterFailure) {
}
