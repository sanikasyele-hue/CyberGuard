package com.cyberguard.incident.service;

import com.cyberguard.incident.dto.LogParseResult;
import com.cyberguard.incident.dto.LogUploadResponse;
import com.cyberguard.incident.entity.SecurityLog;
import com.cyberguard.incident.entity.User;
import com.cyberguard.incident.enums.EventType;
import com.cyberguard.incident.enums.LogStatus;
import com.cyberguard.incident.repository.SecurityLogRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.web.multipart.MultipartFile;

import java.io.IOException;
import java.util.List;
import java.util.Set;
import java.util.stream.Collectors;

@Service
@RequiredArgsConstructor
public class LogIngestionService {

    private static final int MAX_ERRORS_RETURNED = 50; // cap so a badly malformed file doesn't return a huge payload

    private final SecurityLogRepository securityLogRepository;
    private final CsvLogParserService csvLogParserService;
    private final ThreatDetectionService threatDetectionService;
    private final CorrelationDetectionService correlationDetectionService; // rules 2 and 3
    private final MlDetectionService mlDetectionService;                   // trained model

    @Transactional
    public LogUploadResponse ingest(MultipartFile file, User uploadedBy) throws IOException {
        List<LogParseResult> results = csvLogParserService.parse(file, uploadedBy);

        List<SecurityLog> validLogs = results.stream()
                .filter(LogParseResult::isValid)
                .map(LogParseResult::getLog)
                .toList();

        List<String> errors = results.stream()
                .filter(r -> !r.isValid())
                .map(LogParseResult::getErrorMessage)
                .limit(MAX_ERRORS_RETURNED)
                .toList();

        List<SecurityLog> saved = securityLogRepository.saveAll(validLogs);

        // Only re-run detection for users who actually had new failed-login events —
        // no point scanning users whose new logs were all successful or unrelated.
        Set<String> usernamesToEvaluate = saved.stream()
                .filter(l -> l.getEventType() == EventType.LOGIN && l.getStatus() == LogStatus.FAILED)
                .map(SecurityLog::getUsername)
                .collect(Collectors.toSet());

        int incidentsCreated = 0;
        for (String username : usernamesToEvaluate) {
            incidentsCreated += threatDetectionService.evaluateUser(username).size();
        }

        // Rule 2: brute force followed by a successful login - re-check every user with a LOGIN event in this file.
        Set<String> loginUsernames = saved.stream()
                .filter(l -> l.getEventType() == EventType.LOGIN)
                .map(SecurityLog::getUsername)
                .collect(Collectors.toSet());
        for (String username : loginUsernames) {
            incidentsCreated += correlationDetectionService.evaluateBruteForceThenSuccess(username).size();
        }

        // Rule 3: password spray - re-check every IP address that had failed logins in this file.
        Set<String> failedIps = saved.stream()
                .filter(l -> l.getEventType() == EventType.LOGIN && l.getStatus() == LogStatus.FAILED
                        && l.getSourceIp() != null)
                .map(SecurityLog::getSourceIp)
                .collect(Collectors.toSet());
        for (String ip : failedIps) {
            incidentsCreated += correlationDetectionService.evaluatePasswordSpray(ip).size();
        }

        // ML pass (runs last): the trained model checks each user's logins and reports patterns that no rule above covered.
        for (String username : loginUsernames) {
            incidentsCreated += mlDetectionService.evaluateUser(username).size();
        }

        return LogUploadResponse.builder()
                .totalRows(results.size())
                .storedCount(saved.size())
                .errorCount(results.size() - saved.size())
                .errors(errors)
                .incidentsCreated(incidentsCreated)
                .build();
    }
}
