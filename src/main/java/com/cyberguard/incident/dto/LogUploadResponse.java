package com.cyberguard.incident.dto;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.util.List;

@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class LogUploadResponse {
    private int totalRows;
    private int storedCount;
    private int errorCount;
    private List<String> errors;       // capped list of row-level error messages
    private int incidentsCreated;
}
