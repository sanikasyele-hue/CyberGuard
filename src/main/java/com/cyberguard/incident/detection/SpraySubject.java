package com.cyberguard.incident.detection;

/**
 * A password-spray incident is about an attacker IP, not one user. We store it in the
 * incident's "affectedUsername" column as "IP 203.0.113.77" so the existing duplicate
 * check keeps working, and use these helpers to recognise it later.
 */
public final class SpraySubject {

    public static final String PREFIX = "IP ";

    private SpraySubject() {
    }

    public static String of(String ip) {
        return PREFIX + ip;
    }

    public static boolean isSpray(String subject) {
        return subject != null && subject.startsWith(PREFIX);
    }

    public static String ipOf(String subject) {
        return subject.substring(PREFIX.length());
    }
}
