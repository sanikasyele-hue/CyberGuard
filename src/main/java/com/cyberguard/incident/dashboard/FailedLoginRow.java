package com.cyberguard.incident.dashboard;

/** One failed login, used to find the top attacking IP addresses. */
public record FailedLoginRow(String sourceIp, String username) {
}
