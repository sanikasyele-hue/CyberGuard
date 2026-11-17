package com.cyberguard.incident.service;

import com.cyberguard.incident.dto.LogParseResult;
import com.cyberguard.incident.entity.SecurityLog;
import com.cyberguard.incident.entity.User;
import com.cyberguard.incident.enums.EventType;
import com.cyberguard.incident.enums.LogStatus;
import com.opencsv.CSVReader;
import com.opencsv.exceptions.CsvValidationException;
import org.springframework.stereotype.Service;
import org.springframework.web.multipart.MultipartFile;

import java.io.IOException;
import java.io.InputStreamReader;
import java.io.Reader;
import java.nio.charset.StandardCharsets;
import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import java.time.format.DateTimeParseException;
import java.util.ArrayList;
import java.util.List;

/**
 * Expected CSV columns (with header row): timestamp,username,eventType,status,sourceIp
 * sourceIp is optional. Accepts a couple of common timestamp formats.
 */
@Service
public class CsvLogParserService {

    private static final List<DateTimeFormatter> TIMESTAMP_FORMATS = List.of(
            DateTimeFormatter.ISO_LOCAL_DATE_TIME,               // 2026-01-15T10:00:00
            DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss"),  // 2026-01-15 10:00:00
            DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm")      // 2026-01-15 10:00
    );

    private static final int MAX_ROWS = 50_000; // sanity cap even though multipart size is capped at 5MB

    public List<LogParseResult> parse(MultipartFile file, User uploadedBy) throws IOException {
        List<LogParseResult> results = new ArrayList<>();

        try (Reader reader = new InputStreamReader(file.getInputStream(), StandardCharsets.UTF_8);
             CSVReader csvReader = new CSVReader(reader)) {

            String[] header = csvReader.readNext(); // consume header row
            if (header == null) {
                throw new IllegalArgumentException("CSV file is empty");
            }

            String[] row;
            int rowNumber = 1; // header was row 0
            while ((row = csvReader.readNext()) != null) {
                rowNumber++;
                if (rowNumber > MAX_ROWS) {
                    results.add(new LogParseResult(null, rowNumber,
                            "File exceeds maximum of " + MAX_ROWS + " rows; truncated"));
                    break;
                }
                results.add(parseRow(row, rowNumber, uploadedBy));
            }
        } catch (CsvValidationException e) {
            throw new IllegalArgumentException("Malformed CSV file: " + e.getMessage(), e);
        }

        return results;
    }

    private LogParseResult parseRow(String[] row, int rowNumber, User uploadedBy) {
        if (row.length < 4) {
            return new LogParseResult(null, rowNumber,
                    "Expected at least 4 columns (timestamp,username,eventType,status), got " + row.length);
        }

        try {
            LocalDateTime timestamp = parseTimestamp(row[0].trim());
            String username = row[1].trim();
            if (username.isEmpty()) {
                return new LogParseResult(null, rowNumber, "Username is empty");
            }

            EventType eventType = EventType.valueOf(row[2].trim().toUpperCase());
            LogStatus status = LogStatus.valueOf(row[3].trim().toUpperCase());
            String sourceIp = row.length > 4 ? row[4].trim() : null;

            SecurityLog log = SecurityLog.builder()
                    .eventTimestamp(timestamp)
                    .username(username)
                    .eventType(eventType)
                    .status(status)
                    .sourceIp((sourceIp == null || sourceIp.isEmpty()) ? null : sourceIp)
                    .rawLine(String.join(",", row))
                    .uploadedBy(uploadedBy)
                    .build();

            return new LogParseResult(log, rowNumber, null);

        } catch (IllegalArgumentException e) {
            // Covers both DateTimeParseException and enum valueOf() failures
            return new LogParseResult(null, rowNumber, "Row " + rowNumber + ": " + e.getMessage());
        }
    }

    private LocalDateTime parseTimestamp(String raw) {
        for (DateTimeFormatter format : TIMESTAMP_FORMATS) {
            try {
                return LocalDateTime.parse(raw, format);
            } catch (DateTimeParseException ignored) {
                // try next format
            }
        }
        throw new IllegalArgumentException("Unrecognized timestamp format: " + raw);
    }
}
