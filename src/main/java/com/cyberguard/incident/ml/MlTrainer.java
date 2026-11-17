package com.cyberguard.incident.ml;

import com.cyberguard.incident.ml.SyntheticDataGenerator.Sample;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Random;

/** Generates data, splits it 80/20, trains, then judges the model on the 20% it has never seen. */
public final class MlTrainer {

    public static final int RULE_THRESHOLD = 5; // the old rule: "5 or more failures = attack"

    private MlTrainer() {
    }

    public static TrainedModel trainDefault() {
        return train(5000, 42L);
    }

    public static TrainedModel train(int sampleCount, long seed) {
        List<Sample> all = new ArrayList<>(SyntheticDataGenerator.generate(sampleCount, seed));
        Collections.shuffle(all, new Random(seed));

        int split = (int) (all.size() * 0.8);
        List<Sample> train = all.subList(0, split);
        List<Sample> test = all.subList(split, all.size());

        double[][] x = new double[train.size()][];
        int[] y = new int[train.size()];
        for (int i = 0; i < train.size(); i++) {
            x[i] = train.get(i).features();
            y[i] = train.get(i).label();
        }
        LogisticRegression model = LogisticRegression.train(x, y, 1500, 0.3, 0.001);

        int[] ml = new int[4];    // tp, fp, tn, fn for the model
        int[] rule = new int[4];  // same for the "5 failures" rule
        for (Sample s : test) {
            count(ml, model.probability(s.features()) >= 0.5, s.label());
            count(rule, s.rawFailures() >= RULE_THRESHOLD, s.label());
        }

        List<Double> weights = new ArrayList<>();
        for (double w : model.weights()) weights.add(Math.round(w * 1000.0) / 1000.0);

        ModelReport report = new ModelReport(
                "Logistic regression (trained from scratch with gradient descent)",
                train.size(), test.size(),
                ModelReport.Metrics.of(ml[0], ml[1], ml[2], ml[3]),
                ModelReport.Metrics.of(rule[0], rule[1], rule[2], rule[3]),
                FeatureExtractor.NAMES, weights,
                "Trained on SIMULATED login behaviour (normal users vs. brute force, distributed, low-and-slow and stuffing attacks). "
                        + "Scores are measured on 20% of that data the model never saw. Real-world accuracy needs a real labelled dataset.");
        return new TrainedModel(model, report);
    }

    private static void count(int[] c, boolean predictedAttack, int label) {
        if (predictedAttack && label == 1) c[0]++;
        else if (predictedAttack) c[1]++;
        else if (label == 0) c[2]++;
        else c[3]++;
    }
}
