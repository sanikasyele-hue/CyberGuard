package com.cyberguard.incident.repository;

import com.cyberguard.incident.entity.Incident;
import com.cyberguard.incident.enums.IncidentCategory;
import com.cyberguard.incident.enums.IncidentSeverity;
import com.cyberguard.incident.enums.IncidentStatus;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;

import java.time.LocalDateTime;
import java.util.List;

public interface IncidentRepository extends JpaRepository<Incident, Long> {

    Page<Incident> findByStatus(IncidentStatus status, Pageable pageable);

    Page<Incident> findBySeverity(IncidentSeverity severity, Pageable pageable);

    // Used by the ML detector: skip a suspicious range if ANY incident (any rule) already covers it.
    List<Incident> findByAffectedUsernameAndStatusNotAndWindowStartLessThanEqualAndWindowEndGreaterThanEqual(
            String affectedUsername, IncidentStatus status, LocalDateTime windowEnd, LocalDateTime windowStart
    );

    /**
     * Finds any still-open incident for the same user/category whose detection
     * window overlaps the newly-detected window. Used by the detection engine
     * to avoid creating duplicate incidents every time it re-scans the same
     * ongoing pattern of failed logins.
     */
    @Query("""
           SELECT i FROM Incident i
           WHERE i.affectedUsername = :username
             AND i.category = :category
             AND i.status <> com.cyberguard.incident.enums.IncidentStatus.CLOSED
             AND i.windowStart <= :windowEnd
             AND i.windowEnd >= :windowStart
           """)
    List<Incident> findOverlappingOpenIncidents(
            @Param("username") String username,
            @Param("category") IncidentCategory category,
            @Param("windowStart") LocalDateTime windowStart,
            @Param("windowEnd") LocalDateTime windowEnd
    );
}
