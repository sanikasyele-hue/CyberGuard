package com.cyberguard.incident.ml;

import com.cyberguard.incident.detection.LogEvent;

import java.time.LocalDateTime;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

/**
 * Turns the LOGIN events of ONE user inside ONE short time window into 7 numbers
 * (the "features") that the machine-learning model understands.
 * The same code is used for training and for real logs, so they always match.
 */
public final class FeatureExtractor {

    public static final List<String> NAMES = List.of(
            "failed attempts (log scale)",
            "share of attempts that failed",
            "different IP addresses",
            "success after a failure",
            "attempts per minute (log scale)",
            "night time (00:00-05:00)",
            "success from a NEW IP",
            "share of failures from PUBLIC IPs");

    private FeatureExtractor() {
    }

    /** true for addresses outside the usual private ranges (10.x, 192.168.x, 172.16-31.x, 127.x). Unknown = not public. */
    static boolean isPublic(String ip) {
        if (ip == null || ip.isBlank()) return false;
        if (ip.startsWith("10.") || ip.startsWith("192.168.") || ip.startsWith("127.")) return false;
        if (ip.startsWith("172.")) {
            try {
                int second = Integer.parseInt(ip.split("\\.")[1]);
                if (second >= 16 && second <= 31) return false;
            } catch (RuntimeException ignored) {
                // not a normal IPv4 address - treat as public
            }
        }
        return true;
    }

    public static int countFailures(List<LogEvent> events) {
        int n = 0;
        for (LogEvent e : events) {
            if (e.failed()) n++;
        }
        return n;
    }

    public static double[] extract(List<LogEvent> windowEvents) {
        if (windowEvents.isEmpty()) {
            return new double[NAMES.size()];
        }
        List<LogEvent> ev = new ArrayList<>(windowEvents);
        ev.sort(Comparator.comparing(LogEvent::time));

        int total = ev.size();
        int failures = 0;
        Set<String> allIps = new HashSet<>();
        Set<String> failureIps = new HashSet<>();
        boolean seenFailure = false;
        boolean successAfterFailure = false;
        boolean successFromNewIp = false;
        boolean night = false;
        int publicFailures = 0;

        for (LogEvent e : ev) {
            if (e.sourceIp() != null) allIps.add(e.sourceIp());
            if (e.time().getHour() < 5) night = true;

            if (e.failed()) {
                failures++;
                seenFailure = true;
                if (e.sourceIp() != null) failureIps.add(e.sourceIp());
                if (isPublic(e.sourceIp())) publicFailures++;
            } else if (seenFailure) {
                successAfterFailure = true;
                if (e.sourceIp() != null && !failureIps.contains(e.sourceIp())) {
                    successFromNewIp = true;
                }
            }
        }

        LocalDateTime first = ev.get(0).time();
        LocalDateTime last = ev.get(total - 1).time();
        double spanMinutes = Math.max(1.0, java.time.Duration.between(first, last).getSeconds() / 60.0);
        double ratePerMinute = total / spanMinutes;

        return new double[]{
                Math.log1p(failures),
                (double) failures / total,
                allIps.size(),
                successAfterFailure ? 1 : 0,
                Math.log1p(ratePerMinute),
                night ? 1 : 0,
                successFromNewIp ? 1 : 0,
                failures == 0 ? 0 : (double) publicFailures / failures
        };
    }
}
