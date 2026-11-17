package com.cyberguard.incident.dto;

import com.cyberguard.incident.entity.SecurityLog;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@AllArgsConstructor
@NoArgsConstructor
public class LogParseResult {
    private SecurityLog log;      // non-null if this row parsed successfully
    private int rowNumber;
    private String errorMessage;  // non-null if this row failed to parse

    public boolean isValid() {
        return errorMessage == null;
    }
}
