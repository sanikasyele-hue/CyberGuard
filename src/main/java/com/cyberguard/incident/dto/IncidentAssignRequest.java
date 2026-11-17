package com.cyberguard.incident.dto;

import jakarta.validation.constraints.NotBlank;
import lombok.Data;

@Data
public class IncidentAssignRequest {

    @NotBlank(message = "Analyst username is required")
    private String analystUsername;
}
