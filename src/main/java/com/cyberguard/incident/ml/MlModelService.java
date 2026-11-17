package com.cyberguard.incident.ml;

import com.cyberguard.incident.detection.LogEvent;
import jakarta.annotation.PostConstruct;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import java.util.List;

/**
 * Trains the model once when the application starts (takes well under a second) and keeps it in memory.
 * If anything goes wrong the application still starts - the ML features are simply switched off.
 */
@Service
public class MlModelService {

    private static final Logger log = LoggerFactory.getLogger(MlModelService.class);

    private final boolean enabled;
    private final double threshold;
    private volatile TrainedModel trained;

    public MlModelService(@Value("${app.ml.enabled:true}") boolean enabled,
                          @Value("${app.ml.threshold:0.8}") double threshold) {
        this.enabled = enabled;
        this.threshold = threshold;
    }

    @PostConstruct
    void trainAtStartup() {
        if (!enabled) {
            log.info("ML is disabled (ML_ENABLED=false).");
            return;
        }
        try {
            trained = MlTrainer.trainDefault();
            ModelReport r = trained.report();
            log.info("ML model trained. Test accuracy {}, F1 {} (old fixed rule on the same data: F1 {}).",
                    String.format("%.3f", r.model().accuracy()), String.format("%.3f", r.model().f1()),
                    String.format("%.3f", r.rulesBaseline().f1()));
        } catch (RuntimeException e) {
            log.warn("ML model could not be trained, ML features are off: {}", e.getMessage());
        }
    }

    public boolean isEnabled() {
        return enabled;
    }

    public boolean isReady() {
        return trained != null;
    }

    public double threshold() {
        return threshold;
    }

    public ModelReport report() {
        return trained == null ? null : trained.report();
    }

    /** Attack probability (0..1) for the LOGIN events of ONE user inside ONE window. */
    public double probability(List<LogEvent> windowEvents) {
        return trained.model().probability(FeatureExtractor.extract(windowEvents));
    }

    /** Suspicious time ranges in one user's login history. Never throws; returns an empty list on any problem. */
    public List<MlFinding> findRanges(List<LogEvent> userLoginEvents, int windowMinutes) {
        if (trained == null) {
            return List.of();
        }
        try {
            return MlDetector.findSuspiciousRanges(userLoginEvents, trained.model(), threshold, windowMinutes);
        } catch (RuntimeException e) {
            log.warn("ML detection skipped: {}", e.getMessage());
            return List.of();
        }
    }
}
