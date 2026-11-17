package com.cyberguard.incident.service;

import com.cyberguard.incident.event.IncidentCreatedEvent;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.scheduling.annotation.Async;
import org.springframework.stereotype.Component;
import org.springframework.transaction.event.TransactionPhase;
import org.springframework.transaction.event.TransactionalEventListener;

/**
 * Runs the AI agents automatically (in the background) after a new incident has been
 * committed to the database. Turn off with AI_AUTO_ANALYZE=false.
 */
@Component
public class IncidentAnalysisListener {

    private static final Logger log = LoggerFactory.getLogger(IncidentAnalysisListener.class);

    private final IncidentAnalysisService analysisService;
    private final boolean autoAnalyze;

    public IncidentAnalysisListener(IncidentAnalysisService analysisService,
                                    @Value("${app.ai.auto-analyze:true}") boolean autoAnalyze) {
        this.analysisService = analysisService;
        this.autoAnalyze = autoAnalyze;
    }

    @Async
    @TransactionalEventListener(phase = TransactionPhase.AFTER_COMMIT, fallbackExecution = true)
    public void onIncidentCreated(IncidentCreatedEvent event) {
        if (!autoAnalyze) {
            return;
        }
        try {
            analysisService.analyze(event.incidentId());
            log.info("AI analysis finished for incident {}", event.incidentId());
        } catch (Exception e) {
            // Never let a background failure affect the upload that triggered it.
            log.warn("AI analysis failed for incident {}: {}", event.incidentId(), e.getMessage());
        }
    }
}
