package com.cyberguard.incident.controller;

import com.cyberguard.incident.dto.IncidentAssignRequest;
import com.cyberguard.incident.dto.IncidentResponse;
import com.cyberguard.incident.dto.IncidentStatusUpdateRequest;
import com.cyberguard.incident.enums.IncidentSeverity;
import com.cyberguard.incident.enums.IncidentStatus;
import com.cyberguard.incident.service.IncidentAnalysisService;
import com.cyberguard.incident.service.IncidentService;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/api/incidents")
@RequiredArgsConstructor
public class IncidentController {

    private final IncidentService incidentService;
    private final IncidentAnalysisService analysisService;

    @GetMapping
    public ResponseEntity<Page<IncidentResponse>> listIncidents(
            @RequestParam(required = false) IncidentStatus status,
            @RequestParam(required = false) IncidentSeverity severity,
            Pageable pageable
    ) {
        return ResponseEntity.ok(incidentService.findAll(status, severity, pageable));
    }

    @GetMapping("/{id}")
    public ResponseEntity<IncidentResponse> getIncident(@PathVariable Long id) {
        return ResponseEntity.ok(incidentService.findById(id));
    }

    /** Runs the 3 AI agents (classify -> risk -> actions + report) and returns the updated incident. */
    @PostMapping("/{id}/analyze")
    public ResponseEntity<IncidentResponse> analyze(@PathVariable Long id) {
        return ResponseEntity.ok(IncidentResponse.from(analysisService.analyze(id)));
    }

    @PatchMapping("/{id}/status")
    public ResponseEntity<IncidentResponse> updateStatus(
            @PathVariable Long id,
            @Valid @RequestBody IncidentStatusUpdateRequest request
    ) {
        return ResponseEntity.ok(incidentService.updateStatus(id, request.getStatus()));
    }

    @PatchMapping("/{id}/assign")
    public ResponseEntity<IncidentResponse> assignAnalyst(
            @PathVariable Long id,
            @Valid @RequestBody IncidentAssignRequest request
    ) {
        return ResponseEntity.ok(incidentService.assignAnalyst(id, request.getAnalystUsername()));
    }
}
