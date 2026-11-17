package com.cyberguard.incident.detection;

import java.time.Duration;
import java.time.LocalDateTime;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.TreeSet;

/**
 * The two correlation rules, as pure functions (no database, no Spring).
 * That makes them easy to unit-test and easy to explain.
 *
 * (The first rule - "N failed logins for one user inside a time window" - lives in
 * ThreatDetectionService and is unchanged.)
 */
public final class DetectionRules {

    private DetectionRules() {
    }

    /**
     * RULE 2 - Brute force followed by a successful login (possible account takeover).
     *
     * For every SUCCESSFUL login, look backwards. If at least minFailures failed logins of the
     * same user happened in the windowMinutes before it (with no other success in between),
     * the attacker may have guessed the password.
     *
     * @param loginEvents all LOGIN events of ONE user
     */
    public static List<Finding> bruteForceThenSuccess(List<LogEvent> loginEvents, int minFailures, int windowMinutes) {
        List<LogEvent> events = sortedCopy(loginEvents);
        List<Finding> findings = new ArrayList<>();

        for (int s = 0; s < events.size(); s++) {
            LogEvent success = events.get(s);
            if (success.failed()) {
                continue;
            }

            int failures = 0;
            int first = -1;
            for (int k = s - 1; k >= 0; k--) {
                LogEvent earlier = events.get(k);
                if (!earlier.failed()) {
                    break; // an earlier success ends the burst
                }
                if (minutesBetween(earlier.time(), success.time()) > windowMinutes) {
                    break; // too long before the success
                }
                failures++;
                first = k;
            }

            if (failures >= minFailures) {
                Set<String> ips = new HashSet<>();
                for (int k = first; k < s; k++) {
                    if (events.get(k).sourceIp() != null) {
                        ips.add(events.get(k).sourceIp());
                    }
                }
                findings.add(new Finding(events.get(first).time(), success.time(), failures, 1,
                        ips.size(), List.of(success.username())));
            }
        }
        return findings;
    }

    /**
     * RULE 3 - Password spray.
     *
     * One source IP fails to log in as many DIFFERENT users inside a time window
     * (at least minAttempts failures against at least minUsers accounts).
     * Typical of an attacker trying one or two passwords on every account.
     *
     * @param failedLoginsFromOneIp all FAILED LOGIN events that came from ONE IP address
     */
    public static List<Finding> passwordSpray(List<LogEvent> failedLoginsFromOneIp,
                                              int minAttempts, int minUsers, int windowMinutes) {
        List<LogEvent> events = sortedCopy(failedLoginsFromOneIp);
        List<Finding> findings = new ArrayList<>();

        int i = 0;
        while (i < events.size()) {
            LocalDateTime anchor = events.get(i).time();
            int j = i;
            while (j + 1 < events.size() && minutesBetween(anchor, events.get(j + 1).time()) <= windowMinutes) {
                j++;
            }

            int attempts = j - i + 1;
            Set<String> users = new TreeSet<>();
            Set<String> ips = new HashSet<>();
            for (int k = i; k <= j; k++) {
                users.add(events.get(k).username());
                if (events.get(k).sourceIp() != null) {
                    ips.add(events.get(k).sourceIp());
                }
            }

            if (attempts >= minAttempts && users.size() >= minUsers) {
                findings.add(new Finding(anchor, events.get(j).time(), attempts, users.size(),
                        ips.size(), new ArrayList<>(users)));
                i = j + 1; // events in this window are accounted for
            } else {
                i++;
            }
        }
        return findings;
    }

    private static List<LogEvent> sortedCopy(List<LogEvent> events) {
        List<LogEvent> copy = new ArrayList<>(events);
        copy.sort(Comparator.comparing(LogEvent::time));
        return copy;
    }

    private static long minutesBetween(LocalDateTime from, LocalDateTime to) {
        return Duration.between(from, to).toMinutes();
    }
}
