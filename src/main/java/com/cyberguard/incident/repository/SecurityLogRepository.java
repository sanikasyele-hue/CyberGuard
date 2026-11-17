package com.cyberguard.incident.repository;

import com.cyberguard.incident.entity.SecurityLog;
import com.cyberguard.incident.enums.EventType;
import com.cyberguard.incident.enums.LogStatus;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.data.jpa.repository.JpaRepository;

import java.time.LocalDateTime;
import java.util.List;

public interface SecurityLogRepository extends JpaRepository<SecurityLog, Long> {

    // Ordered ascending so the detection engine's sliding window can scan chronologically.
    List<SecurityLog> findByUsernameAndEventTypeAndStatusOrderByEventTimestampAsc(
            String username, EventType eventType, LogStatus status
    );

    Page<SecurityLog> findByUsernameContainingIgnoreCase(String username, Pageable pageable);

    // Rule 2 (brute force then success): all LOGIN events of one user, oldest first.
    List<SecurityLog> findByUsernameAndEventTypeOrderByEventTimestampAsc(String username, EventType eventType);

    // Rule 3 (password spray): failed logins that came from one IP address.
    List<SecurityLog> findBySourceIpAndEventTypeAndStatusOrderByEventTimestampAsc(
            String sourceIp, EventType eventType, LogStatus status
    );

    // Evidence lookup for the AI agents when the incident is about an IP (password spray).
    List<SecurityLog> findBySourceIpAndEventTimestampBetweenOrderByEventTimestampAsc(
            String sourceIp, LocalDateTime from, LocalDateTime to
    );

    // Dashboard numbers.
    long countByEventTypeAndStatus(EventType eventType, LogStatus status);

    List<SecurityLog> findByEventTypeAndStatusAndSourceIpIsNotNull(EventType eventType, LogStatus status);

    // Evidence lookup for the AI agents: everything one user did in a time range.
    List<SecurityLog> findByUsernameAndEventTimestampBetweenOrderByEventTimestampAsc(
            String username, LocalDateTime from, LocalDateTime to
    );
}
