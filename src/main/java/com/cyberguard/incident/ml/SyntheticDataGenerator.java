package com.cyberguard.incident.ml;

import com.cyberguard.incident.detection.LogEvent;

import java.time.LocalDateTime;
import java.util.ArrayList;
import java.util.List;
import java.util.Random;

/**
 * Creates labelled training examples by SIMULATING login behaviour.
 * Label 1 = attack, label 0 = normal. The label comes from the simulated scenario,
 * NOT from the detection rules, so the model learns from ground truth.
 *
 * IMPORTANT (be honest in the viva): this is simulated data. It proves the pipeline
 * (features -> training -> evaluation -> scoring) works. To claim real-world accuracy
 * you would train on a real labelled dataset.
 */
public final class SyntheticDataGenerator {

    /** One training example. rawFailures is only used to evaluate the old "5 failures" rule on the same data. */
    public record Sample(double[] features, int label, int rawFailures) {
    }

    private SyntheticDataGenerator() {
    }

    public static List<Sample> generate(int count, long seed) {
        Random rnd = new Random(seed);
        List<Sample> samples = new ArrayList<>(count);
        for (int i = 0; i < count; i++) {
            boolean attack = rnd.nextDouble() < 0.40;
            List<LogEvent> window = attack ? attackWindow(rnd) : normalWindow(rnd);
            samples.add(new Sample(FeatureExtractor.extract(window), attack ? 1 : 0,
                    FeatureExtractor.countFailures(window)));
        }
        return samples;
    }

    // ---------------- normal behaviour (label 0) ----------------
    // Includes harmless things that LOOK suspicious (forgotten passwords, new phone, broken scripts),
    // because real data is messy and the model must learn to tell them apart.

    private static List<LogEvent> normalWindow(Random rnd) {
        // 80% of normal users log in from the office network, 20% work remotely from a home (public) IP
        String ip = rnd.nextDouble() < 0.2 ? randomIp(rnd, "49.36.12.") : randomIp(rnd, "192.168.1.");
        LocalDateTime t = start(rnd, 0.85); // mostly working hours
        List<LogEvent> ev = new ArrayList<>();
        double kind = rnd.nextDouble();

        if (kind < 0.35) {                       // normal: one to three successful logins
            int n = 1 + rnd.nextInt(3);
            for (int i = 0; i < n; i++) ev.add(event(t = t.plusSeconds(20 + rnd.nextInt(120)), ip, false));
        } else if (kind < 0.52) {                // typo: 1-2 failures, then success
            int f = 1 + rnd.nextInt(2);
            for (int i = 0; i < f; i++) ev.add(event(t = t.plusSeconds(5 + rnd.nextInt(30)), ip, true));
            ev.add(event(t.plusSeconds(10 + rnd.nextInt(40)), ip, false));
        } else if (kind < 0.67) {                // forgot password: 3-5 failures, then success from the same IP
            int f = 3 + rnd.nextInt(3);
            for (int i = 0; i < f; i++) ev.add(event(t = t.plusSeconds(15 + rnd.nextInt(60)), ip, true));
            ev.add(event(t.plusSeconds(20 + rnd.nextInt(60)), ip, false));
        } else if (kind < 0.75) {                // forgot password, then logs in from another device (new IP)
            t = start(rnd, 0.75);
            int f = 3 + rnd.nextInt(2);
            for (int i = 0; i < f; i++) ev.add(event(t = t.plusSeconds(15 + rnd.nextInt(60)), ip, true));
            ev.add(event(t.plusSeconds(30 + rnd.nextInt(90)), randomIp(rnd, "10.0.5."), false));
        } else if (kind < 0.85) {                // busy user: many successful logins
            int n = 5 + rnd.nextInt(10);
            for (int i = 0; i < n; i++) ev.add(event(t = t.plusSeconds(10 + rnd.nextInt(40)), ip, false));
        } else if (kind < 0.92) {                // broken script / expired service password: many regular failures from one internal IP
            t = start(rnd, 0.5);
            int f = 6 + rnd.nextInt(9);
            for (int i = 0; i < f; i++) ev.add(event(t = t.plusSeconds(10 + rnd.nextInt(25)), "10.0.0." + (1 + rnd.nextInt(20)), true));
        } else {                                 // night-shift worker: night logins with 0-2 failures
            t = LocalDateTime.of(2026, 1, 1, rnd.nextInt(5), rnd.nextInt(60), rnd.nextInt(60));
            int f = rnd.nextInt(3);
            for (int i = 0; i < f; i++) ev.add(event(t = t.plusSeconds(10 + rnd.nextInt(40)), ip, true));
            ev.add(event(t.plusSeconds(10 + rnd.nextInt(40)), ip, false));
        }
        return ev;
    }

    // ---------------- attacks (label 1) ----------------

    private static List<LogEvent> attackWindow(Random rnd) {
        List<LogEvent> ev = new ArrayList<>();
        double kind = rnd.nextDouble();

        if (kind < 0.25) {                       // fast brute force: many failures from 1-2 IPs
            String ip = attackIp(rnd, "198.51.100.");
            String ip2 = rnd.nextBoolean() ? ip : randomIp(rnd, "203.0.113.");
            LocalDateTime t = start(rnd, 0.4);
            int f = 6 + rnd.nextInt(35);
            for (int i = 0; i < f; i++) ev.add(event(t = t.plusSeconds(1 + rnd.nextInt(14)), i % 2 == 0 ? ip : ip2, true));
            if (rnd.nextDouble() < 0.35) ev.add(event(t.plusSeconds(5 + rnd.nextInt(20)), ip, false));
        } else if (kind < 0.40) {                // distributed: failures spread over several IPs
            int ips = 3 + rnd.nextInt(4);
            LocalDateTime t = start(rnd, 0.4);
            int f = 8 + rnd.nextInt(23);
            String last = "";
            for (int i = 0; i < f; i++) {
                last = randomIp(rnd, "45.33." + (i % ips) + ".");
                ev.add(event(t = t.plusSeconds(5 + rnd.nextInt(35)), last, true));
            }
            if (rnd.nextDouble() < 0.30) ev.add(event(t.plusSeconds(10 + rnd.nextInt(30)), last, false));
        } else if (kind < 0.65) {                // low-and-slow takeover: only 2-5 failures, then a success
            LocalDateTime t = start(rnd, 0.5);
            int f = 2 + rnd.nextInt(4);
            String attackerIp = attackIp(rnd, "91.240.118.");
            for (int i = 0; i < f; i++) ev.add(event(t = t.plusSeconds(20 + rnd.nextInt(100)), attackerIp, true));
            boolean newIp = rnd.nextDouble() < 0.8; // 20% of attackers log in from the same IP they failed from
            ev.add(event(t.plusSeconds(15 + rnd.nextInt(60)), newIp ? attackIp(rnd, "185.220.101.") : attackerIp, false));
        } else if (kind < 0.75) {                // credential stuffing burst: 5-12 failures in about a minute
            LocalDateTime t = start(rnd, 0.4);
            int f = 5 + rnd.nextInt(8);
            int ips = 2 + rnd.nextInt(2);
            for (int i = 0; i < f; i++) ev.add(event(t = t.plusSeconds(1 + rnd.nextInt(8)), randomIp(rnd, "103.75." + (i % ips) + "."), true));
        } else if (kind < 0.90) {                // slow brute force: 5-10 failures, 20-55 s apart, one IP
            LocalDateTime t = start(rnd, 0.6);
            String ip = attackIp(rnd, "198.51.100.");
            int f = 5 + rnd.nextInt(6);
            for (int i = 0; i < f; i++) ev.add(event(t = t.plusSeconds(20 + rnd.nextInt(36)), ip, true));
            if (rnd.nextDouble() < 0.25) ev.add(event(t.plusSeconds(20 + rnd.nextInt(40)), ip, false));
        } else {                                 // probing: 3-4 quick failures from an outside IP, no success
            LocalDateTime t = start(rnd, 0.5);
            String ip = attackIp(rnd, "185.220.101.");
            int f = 3 + rnd.nextInt(2);
            for (int i = 0; i < f; i++) ev.add(event(t = t.plusSeconds(2 + rnd.nextInt(5)), ip, true));
        }
        return ev;
    }

    // ---------------- helpers ----------------

    private static LogEvent event(LocalDateTime time, String ip, boolean failed) {
        return new LogEvent(time, "user", ip, failed);
    }

    /** dayShare = chance the window starts in normal working hours (07:00-20:00); otherwise any hour. */
    private static LocalDateTime start(Random rnd, double dayShare) {
        int hour = rnd.nextDouble() < dayShare ? 7 + rnd.nextInt(13) : rnd.nextInt(24);
        return LocalDateTime.of(2026, 1, 1, hour, rnd.nextInt(60), rnd.nextInt(60));
    }

    /** Attackers are usually outside (public IP) but 15% are insiders / compromised internal machines. */
    private static String attackIp(Random rnd, String publicPrefix) {
        return rnd.nextDouble() < 0.15 ? randomIp(rnd, "192.168.1.") : randomIp(rnd, publicPrefix);
    }

    private static String randomIp(Random rnd, String prefix) {
        return prefix + (1 + rnd.nextInt(250));
    }
}
