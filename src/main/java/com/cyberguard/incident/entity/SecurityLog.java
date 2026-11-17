package com.cyberguard.incident.entity;

import com.cyberguard.incident.enums.EventType;
import com.cyberguard.incident.enums.LogStatus;
import jakarta.persistence.*;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.time.LocalDateTime;

@Entity
@Table(
    name = "security_logs",
    indexes = {
        // Detection queries filter by username + event_type + status + timestamp constantly —
        // this composite index keeps the sliding-window scan fast as log volume grows.
        @Index(name = "idx_logs_username_event_status_time",
               columnList = "username, eventType, status, eventTimestamp")
    }
)
@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class SecurityLog {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(nullable = false)
    private LocalDateTime eventTimestamp;

    @Column(nullable = false, length = 100)
    private String username;

    @Enumerated(EnumType.STRING)
    @Column(nullable = false, length = 30)
    private EventType eventType;

    @Enumerated(EnumType.STRING)
    @Column(nullable = false, length = 20)
    private LogStatus status;

    @Column(length = 45) // long enough for IPv6
    private String sourceIp;

    // Original raw CSV line, kept for audit/debugging — lets an analyst verify
    // exactly what was ingested if a parsing dispute ever comes up.
    @Column(length = 500)
    private String rawLine;

    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "uploaded_by_user_id")
    private User uploadedBy;

    @Column(updatable = false)
    private LocalDateTime uploadedAt;

    @PrePersist
    protected void onCreate() {
        this.uploadedAt = LocalDateTime.now();
    }
}
