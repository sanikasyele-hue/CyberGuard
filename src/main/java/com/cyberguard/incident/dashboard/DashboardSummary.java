package com.cyberguard.incident.dashboard;

import java.util.List;
import java.util.Map;

/** JSON returned by GET /api/dashboard/summary. */
public record DashboardSummary(
        Totals totals,
        Map<String, Integer> bySeverity,
        Map<String, Integer> byStatus,
        Map<String, Integer> byCategory,
        List<DayCount> incidentsOverTime,
        List<IpStat> topAttackingIps,
        List<RecentIncident> recentIncidents
) {
    public record Totals(int totalIncidents, int activeIncidents, int criticalActive, int aiAnalysed,
                         long totalLogs, long failedLogins) {
    }

    public record DayCount(String date, int count) {
    }

    public record IpStat(String ip, long failedAttempts, long targetedUsers) {
    }

    public record RecentIncident(Long id, String title, String severity, String status, String subject) {
    }
}
