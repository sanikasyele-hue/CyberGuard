package com.cyberguard.incident.ml;

/** A trained model plus its evaluation report. */
public record TrainedModel(LogisticRegression model, ModelReport report) {
}
