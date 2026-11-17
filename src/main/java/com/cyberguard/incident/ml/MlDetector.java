package com.cyberguard.incident.ml;

import com.cyberguard.incident.detection.LogEvent;

import java.time.Duration;
import java.time.LocalDateTime;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.List;

/**
 * Slides a window over one user's LOGIN events, asks the model "attack or not?" for each window,
 * and merges neighbouring suspicious windows into time ranges.
 */
public final class MlDetector {

    private static final int MAX_EVENTS = 2000; // safety cap for very large users

    private MlDetector() {
    }

    public static List<MlFinding> findSuspiciousRanges(List<LogEvent> userLoginEvents, LogisticRegression model,
                                                       double threshold, int windowMinutes) {
        List<LogEvent> events = new ArrayList<>(userLoginEvents);
        events.sort(Comparator.comparing(LogEvent::time));
        if (events.size() > MAX_EVENTS) {
            events = new ArrayList<>(events.subList(events.size() - MAX_EVENTS, events.size()));
        }

        List<MlFinding> ranges = new ArrayList<>();
        for (int end = 0; end < events.size(); end++) {
            LocalDateTime endTime = events.get(end).time();
            int first = end;
            while (first > 0 && Duration.between(events.get(first - 1).time(), endTime).toMinutes() < windowMinutes) {
                first--;
            }
            List<LogEvent> window = events.subList(first, end + 1);
            double[] f = FeatureExtractor.extract(window);
            double p = model.probability(f);
            if (p < threshold) {
                continue;
            }

            MlFinding found = new MlFinding(events.get(first).time(), endTime, p, window.size(),
                    FeatureExtractor.countFailures(window), f[3] == 1.0);
            MlFinding lastRange = ranges.isEmpty() ? null : ranges.get(ranges.size() - 1);
            if (lastRange != null && !found.start().isAfter(lastRange.end())) {
                ranges.set(ranges.size() - 1, merge(lastRange, found)); // overlapping -> one range
            } else {
                ranges.add(found);
            }
        }
        return ranges;
    }

    private static MlFinding merge(MlFinding a, MlFinding b) {
        return new MlFinding(
                a.start().isBefore(b.start()) ? a.start() : b.start(),
                a.end().isAfter(b.end()) ? a.end() : b.end(),
                Math.max(a.probability(), b.probability()),
                Math.max(a.eventCount(), b.eventCount()),
                Math.max(a.failures(), b.failures()),
                a.successAfterFailure() || b.successAfterFailure());
    }
}
