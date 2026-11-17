package com.cyberguard.incident.dto;

import com.cyberguard.incident.entity.SecurityLog;
import com.cyberguard.incident.enums.EventType;
import com.cyberguard.incident.enums.LogStatus;
import lombok.Builder;
import lombok.Data;

import java.time.LocalDateTime;

/**
 * What the API returns for a log row. Returning the entity directly crashed with
 * HTTP 500 because its "uploadedBy" user is lazy-loaded; this flat copy avoids that.
 */
@Data
@Builder
public class SecurityLogResponse {
    private Long id;
    private LocalDateTime eventTimestamp;
    private String username;
    private EventType eventType;
    private LogStatus status;
    private String sourceIp;
    private String uploadedBy;
    private LocalDateTime uploadedAt;

    public static SecurityLogResponse from(SecurityLog log) {
        return SecurityLogResponse.builder()
                .id(log.getId())
                .eventTimestamp(log.getEventTimestamp())
                .username(log.getUsername())
                .eventType(log.getEventType())
                .status(log.getStatus())
                .sourceIp(log.getSourceIp())
                .uploadedBy(log.getUploadedBy() != null ? log.getUploadedBy().getUsername() : null)
                .uploadedAt(log.getUploadedAt())
                .build();
    }
}
