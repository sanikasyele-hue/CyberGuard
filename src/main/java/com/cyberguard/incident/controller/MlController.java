package com.cyberguard.incident.controller;

import com.cyberguard.incident.ml.MlModelService;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.LinkedHashMap;
import java.util.Map;

/** Shows how the ML model was trained and how well it did. /api/ml/** is limited to ADMIN and SECURITY_ANALYST. */
@RestController
@RequestMapping("/api/ml")
public class MlController {

    private final MlModelService mlModelService;

    public MlController(MlModelService mlModelService) {
        this.mlModelService = mlModelService;
    }

    @GetMapping("/status")
    public ResponseEntity<Map<String, Object>> status() {
        Map<String, Object> body = new LinkedHashMap<>();
        body.put("enabled", mlModelService.isEnabled());
        body.put("ready", mlModelService.isReady());
        body.put("threshold", mlModelService.threshold());
        body.put("report", mlModelService.report());
        return ResponseEntity.ok(body);
    }
}
