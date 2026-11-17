package com.cyberguard.incident.controller;

import com.cyberguard.incident.dto.LogUploadResponse;
import com.cyberguard.incident.dto.SecurityLogResponse;
import com.cyberguard.incident.entity.User;
import com.cyberguard.incident.repository.UserRepository;
import com.cyberguard.incident.repository.SecurityLogRepository;
import com.cyberguard.incident.security.UserPrincipal;
import com.cyberguard.incident.service.LogIngestionService;
import lombok.RequiredArgsConstructor;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.multipart.MultipartFile;

import java.io.IOException;

@RestController
@RequestMapping("/api/logs")
@RequiredArgsConstructor
public class LogController {

    private final LogIngestionService logIngestionService;
    private final SecurityLogRepository securityLogRepository;
    private final UserRepository userRepository;

    @PostMapping(value = "/upload", consumes = "multipart/form-data")
    public ResponseEntity<LogUploadResponse> uploadLogs(
            @RequestParam("file") MultipartFile file,
            @AuthenticationPrincipal UserPrincipal principal
    ) throws IOException {
        if (file.isEmpty()) {
            return ResponseEntity.badRequest().build();
        }

        User uploader = userRepository.findById(principal.getId())
                .orElseThrow(() -> new IllegalStateException("Authenticated user not found"));

        LogUploadResponse response = logIngestionService.ingest(file, uploader);
        return ResponseEntity.ok(response);
    }

    @GetMapping
    public ResponseEntity<Page<SecurityLogResponse>> listLogs(
            @RequestParam(required = false, defaultValue = "") String username,
            Pageable pageable
    ) {
        return ResponseEntity.ok(
                securityLogRepository.findByUsernameContainingIgnoreCase(username, pageable)
                        .map(SecurityLogResponse::from));
    }
}
