package com.cyberguard.incident.ml;

import java.util.List;

/** Everything shown on the dashboard about the trained model. */
public record ModelReport(
        String algorithm,
        int trainSamples,
        int testSamples,
        Metrics model,
        Metrics rulesBaseline,
        List<String> featureNames,
        List<Double> featureWeights,
        String dataNote
) {
    public record Metrics(double accuracy, double precision, double recall, double f1,
                          int truePositives, int falsePositives, int trueNegatives, int falseNegatives) {

        public static Metrics of(int tp, int fp, int tn, int fn) {
            double total = tp + fp + tn + fn;
            double precision = tp + fp == 0 ? 0 : (double) tp / (tp + fp);
            double recall = tp + fn == 0 ? 0 : (double) tp / (tp + fn);
            double f1 = precision + recall == 0 ? 0 : 2 * precision * recall / (precision + recall);
            return new Metrics(total == 0 ? 0 : (tp + tn) / total, precision, recall, f1, tp, fp, tn, fn);
        }
    }
}
