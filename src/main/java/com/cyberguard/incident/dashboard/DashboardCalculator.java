package com.cyberguard.incident.dashboard;

import com.cyberguard.incident.dashboard.DashboardSummary.DayCount;
import com.cyberguard.incident.dashboard.DashboardSummary.IpStat;
import com.cyberguard.incident.dashboard.DashboardSummary.RecentIncident;
import com.cyberguard.incident.dashboard.DashboardSummary.Totals;
import com.cyberguard.incident.enums.IncidentCategory;
import com.cyberguard.incident.enums.IncidentSeverity;
import com.cyberguard.incident.enums.IncidentStatus;

import java.time.LocalDate;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.HashMap;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.TreeMap;

/** All dashboard numbers are calculated here, from plain lists. No database, no Spring. */
public final class DashboardCalculator {

    private static final int MAX_DAYS = 30;
    private static final int TOP_IPS = 5;
    private static final int RECENT = 5;

    private DashboardCalculator() {
    }

    public static DashboardSummary build(List<IncidentRow> incidents, long totalLogs, long failedLogins,
                                         List<FailedLoginRow> failedLoginRows) {

        Map<String, Integer> bySeverity = new LinkedHashMap<>();
        for (IncidentSeverity s : IncidentSeverity.values()) bySeverity.put(s.name(), 0);
        Map<String, Integer> byStatus = new LinkedHashMap<>();
        for (IncidentStatus s : IncidentStatus.values()) byStatus.put(s.name(), 0);
        Map<String, Integer> byCategory = new LinkedHashMap<>();
        for (IncidentCategory c : IncidentCategory.values()) byCategory.put(c.name(), 0);

        TreeMap<LocalDate, Integer> perDay = new TreeMap<>();
        int active = 0;
        int criticalActive = 0;
        int analysed = 0;

        for (IncidentRow r : incidents) {
            bySeverity.merge(r.severity().name(), 1, Integer::sum);
            byStatus.merge(r.status().name(), 1, Integer::sum);
            byCategory.merge(r.category().name(), 1, Integer::sum);
            perDay.merge(r.windowStart().toLocalDate(), 1, Integer::sum);

            boolean isActive = r.status() != IncidentStatus.RESOLVED && r.status() != IncidentStatus.CLOSED;
            if (isActive) active++;
            if (isActive && r.severity() == IncidentSeverity.CRITICAL) criticalActive++;
            if (r.aiAnalysed()) analysed++;
        }

        List<DayCount> days = new ArrayList<>();
        for (Map.Entry<LocalDate, Integer> e : perDay.entrySet()) {
            days.add(new DayCount(e.getKey().toString(), e.getValue()));
        }
        if (days.size() > MAX_DAYS) {
            days = new ArrayList<>(days.subList(days.size() - MAX_DAYS, days.size()));
        }

        List<RecentIncident> recent = incidents.stream()
                .sorted(Comparator.comparing(IncidentRow::id).reversed())
                .limit(RECENT)
                .map(r -> new RecentIncident(r.id(), r.title(), r.severity().name(), r.status().name(), r.subject()))
                .toList();

        return new DashboardSummary(
                new Totals(incidents.size(), active, criticalActive, analysed, totalLogs, failedLogins),
                bySeverity, byStatus, byCategory, days, topIps(failedLoginRows), recent);
    }

    private static List<IpStat> topIps(List<FailedLoginRow> rows) {
        Map<String, Integer> attempts = new HashMap<>();
        Map<String, Set<String>> users = new HashMap<>();
        for (FailedLoginRow r : rows) {
            if (r.sourceIp() == null || r.sourceIp().isBlank()) continue;
            attempts.merge(r.sourceIp(), 1, Integer::sum);
            users.computeIfAbsent(r.sourceIp(), k -> new HashSet<>()).add(r.username());
        }
        return attempts.entrySet().stream()
                .sorted(Map.Entry.<String, Integer>comparingByValue().reversed().thenComparing(Map.Entry.comparingByKey()))
                .limit(TOP_IPS)
                .map(e -> new IpStat(e.getKey(), e.getValue(), users.get(e.getKey()).size()))
                .toList();
    }
}
