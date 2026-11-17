package com.cyberguard.incident.dto;

import com.cyberguard.incident.enums.IncidentStatus;
import jakarta.validation.constraints.NotNull;
import lombok.Data;

@Data
public class IncidentStatusUpdateRequest {

    @NotNull(message = "Status is required")
    private IncidentStatus status;
}
