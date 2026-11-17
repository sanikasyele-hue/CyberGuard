package com.cyberguard.incident.ml;

/**
 * Logistic regression = a classic supervised machine-learning model.
 * It learns one weight per feature from labelled examples (0 = normal, 1 = attack) using
 * gradient descent, then outputs the probability that a new example is an attack.
 * Written from scratch (no library) so every line can be explained.
 */
public final class LogisticRegression {

    private final double[] weights;   // learned importance of each feature (on standardised inputs)
    private final double bias;
    private final double[] mean;      // used to standardise inputs
    private final double[] std;

    private LogisticRegression(double[] weights, double bias, double[] mean, double[] std) {
        this.weights = weights;
        this.bias = bias;
        this.mean = mean;
        this.std = std;
    }

    /** Learns from the examples. epochs = passes over the data, learningRate = step size, l2 = overfitting guard. */
    public static LogisticRegression train(double[][] x, int[] y, int epochs, double learningRate, double l2) {
        int n = x.length;
        int d = x[0].length;

        double[] mean = new double[d];
        double[] std = new double[d];
        for (int j = 0; j < d; j++) {
            double sum = 0;
            for (double[] row : x) sum += row[j];
            mean[j] = sum / n;
            double var = 0;
            for (double[] row : x) var += (row[j] - mean[j]) * (row[j] - mean[j]);
            std[j] = Math.sqrt(var / n);
            if (std[j] < 1e-9) std[j] = 1.0;
        }

        double[][] z = new double[n][d];
        for (int i = 0; i < n; i++) {
            for (int j = 0; j < d; j++) z[i][j] = (x[i][j] - mean[j]) / std[j];
        }

        double[] w = new double[d];
        double b = 0;
        for (int epoch = 0; epoch < epochs; epoch++) {
            double[] gradW = new double[d];
            double gradB = 0;
            for (int i = 0; i < n; i++) {
                double error = sigmoid(dot(w, z[i]) + b) - y[i]; // prediction minus truth
                for (int j = 0; j < d; j++) gradW[j] += error * z[i][j];
                gradB += error;
            }
            for (int j = 0; j < d; j++) w[j] -= learningRate * (gradW[j] / n + l2 * w[j]);
            b -= learningRate * (gradB / n);
        }
        return new LogisticRegression(w, b, mean, std);
    }

    /** Probability (0..1) that the example is an attack. */
    public double probability(double[] features) {
        double s = bias;
        for (int j = 0; j < weights.length; j++) {
            s += weights[j] * ((features[j] - mean[j]) / std[j]);
        }
        return sigmoid(s);
    }

    public double[] weights() {
        return weights.clone();
    }

    private static double dot(double[] a, double[] b) {
        double s = 0;
        for (int i = 0; i < a.length; i++) s += a[i] * b[i];
        return s;
    }

    private static double sigmoid(double v) {
        if (v >= 0) {
            return 1.0 / (1.0 + Math.exp(-v));
        }
        double e = Math.exp(v);
        return e / (1.0 + e);
    }
}
