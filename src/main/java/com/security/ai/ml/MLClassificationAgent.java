package com.security.ai.ml;

import com.security.ai.agent.AbstractSecurityAgent;
import com.security.ai.agent.SecurityAgent;
import org.tribuo.Dataset;
import org.tribuo.Model;
import org.tribuo.MutableDataset;
import org.tribuo.classification.Label;
import org.tribuo.classification.LabelFactory;
import org.tribuo.classification.evaluation.LabelEvaluation;
import org.tribuo.classification.evaluation.LabelEvaluator;
import org.tribuo.classification.sgd.linear.LogisticRegressionTrainer;
import org.tribuo.data.csv.CSVLoader;
import org.tribuo.util.Util;

import java.io.IOException;
import java.nio.file.Path;
import java.util.*;
import java.util.concurrent.ConcurrentHashMap;

/**
 * ML-based classification agent using Tribuo for vulnerability risk assessment.
 * Uses machine learning to classify and prioritize security findings.
 */
public class MLClassificationAgent extends AbstractSecurityAgent {
    
    private Model<Label> vulnerabilityClassifier;
    private final VulnerabilityFeatureExtractor featureExtractor;
    private final Map<String, VulnerabilityRiskScore> riskCache = new ConcurrentHashMap<>();
    private final LabelFactory labelFactory = new LabelFactory();
    
    public MLClassificationAgent() {
        super();
        this.featureExtractor = new VulnerabilityFeatureExtractor();
    }
    
    @Override
    public AgentType getType() {
        return AgentType.ML_CLASSIFIER;
    }
    
    @Override
    protected void initialize() throws Exception {
        logger.info("Initializing ML Classification Agent");
        
        // Train or load pre-trained model
        trainOrLoadModel();
        
        status.set(AgentStatus.RUNNING);
    }
    
    @Override
    protected void runAgentLoop() throws Exception {
        while (status.get() == AgentStatus.RUNNING) {
            try {
                Thread.sleep(10000); // Check every 10 seconds
                
                // Periodic model retraining with new data
                if (shouldRetrainModel()) {
                    retrainModel();
                }
                
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
                break;
            }
        }
    }
    
    @Override
    protected List<SecurityFinding> performAnalysis(SecurityEvent event) throws Exception {
        List<SecurityFinding> findings = new ArrayList<>();
        
        // If event contains existing findings, enhance them with ML classification
        if (event.payload() instanceof List<?> existingFindings) {
            for (Object obj : existingFindings) {
                if (obj instanceof SecurityFinding finding) {
                    findings.add(enhanceFindingWithML(finding));
                }
            }
        }
        
        return findings;
    }
    
    /**
     * Enhance security finding with ML-based risk assessment
     */
    private SecurityFinding enhanceFindingWithML(SecurityFinding finding) {
        try {
            // Extract features from finding
            VulnerabilityFeatures features = featureExtractor.extract(finding);
            
            // Classify using ML model
            VulnerabilityRiskScore riskScore = classifyVulnerability(features);
            
            // Cache risk score
            riskCache.put(finding.findingId(), riskScore);
            
            // Update finding with ML-enhanced information
            return new SecurityFinding(
                finding.findingId(),
                finding.detectedAt(),
                adjustSeverityBasedOnML(finding.severity(), riskScore),
                finding.category(),
                finding.description() + " [ML Risk: " + riskScore.riskLevel() + "]",
                finding.location(),
                finding.cveId(),
                riskScore.confidence(),
                finding.recommendations(),
                riskScore.exploitability() > 0.7
            );
            
        } catch (Exception e) {
            logger.error("ML classification failed for finding: {}", finding.findingId(), e);
            return finding;
        }
    }
    
    /**
     * Classify vulnerability using ML model
     */
    private VulnerabilityRiskScore classifyVulnerability(VulnerabilityFeatures features) {
        // Create Tribuo example from features
        var example = featureExtractor.createExample(features, labelFactory);
        
        // Predict using trained model
        var prediction = vulnerabilityClassifier.predict(example);
        
        // Calculate risk metrics
        double confidence = prediction.getOutput().getScore();
        String riskLevel = prediction.getOutput().getLabel();
        double exploitability = calculateExploitability(features);
        double impact = calculateImpact(features);
        
        return new VulnerabilityRiskScore(
            riskLevel,
            confidence,
            exploitability,
            impact,
            calculateCVSSScore(exploitability, impact)
        );
    }
    
    /**
     * Adjust severity based on ML risk assessment
     */
    private SecurityFinding.Severity adjustSeverityBasedOnML(
        SecurityFinding.Severity originalSeverity,
        VulnerabilityRiskScore riskScore
    ) {
        // If ML confidence is high, potentially upgrade severity
        if (riskScore.confidence() > 0.9 && riskScore.exploitability() > 0.8) {
            return switch (originalSeverity) {
                case HIGH -> SecurityFinding.Severity.CRITICAL;
                case MEDIUM -> SecurityFinding.Severity.HIGH;
                case LOW -> SecurityFinding.Severity.MEDIUM;
                default -> originalSeverity;
            };
        }
        
        // If ML confidence is low, potentially downgrade severity
        if (riskScore.confidence() < 0.5 && riskScore.exploitability() < 0.3) {
            return switch (originalSeverity) {
                case CRITICAL -> SecurityFinding.Severity.HIGH;
                case HIGH -> SecurityFinding.Severity.MEDIUM;
                case MEDIUM -> SecurityFinding.Severity.LOW;
                default -> originalSeverity;
            };
        }
        
        return originalSeverity;
    }
    
    /**
     * Train or load pre-trained ML model
     */
    private void trainOrLoadModel() throws Exception {
        logger.info("Training ML model for vulnerability classification");
        
        // Create training dataset with synthetic data
        MutableDataset<Label> trainingData = createTrainingDataset();
        
        // Train logistic regression classifier
        LogisticRegressionTrainer trainer = new LogisticRegressionTrainer();
        vulnerabilityClassifier = trainer.train(trainingData);
        
        // Evaluate model
        evaluateModel(trainingData);
        
        logger.info("ML model training completed");
    }
    
    /**
     * Create training dataset for vulnerability classification
     */
    private MutableDataset<Label> createTrainingDataset() {
        MutableDataset<Label> dataset = new MutableDataset<Label>(
            new org.tribuo.DataSource<Label>() {
                @Override
                public org.tribuo.provenance.DataSourceProvenance getProvenance() {
                    return new org.tribuo.provenance.SimpleDataSourceProvenance("Training", labelFactory);
                }
                @Override
                public java.util.Iterator<org.tribuo.Example<Label>> iterator() {
                    return java.util.Collections.emptyIterator();
                }
                @Override
                public org.tribuo.OutputFactory<Label> getOutputFactory() {
                    return labelFactory;
                }
            }
        );
        
        // In production, load real vulnerability data
        // For demo purposes, we create synthetic examples
        
        // Critical vulnerabilities
        dataset.add(featureExtractor.createExample(
            new VulnerabilityFeatures("SQL_INJECTION", 0.95, true, true, 9.8),
            new Label("CRITICAL")
        ));
        
        dataset.add(featureExtractor.createExample(
            new VulnerabilityFeatures("REMOTE_CODE_EXECUTION", 0.98, true, true, 10.0),
            new Label("CRITICAL")
        ));
        
        // High severity vulnerabilities
        dataset.add(featureExtractor.createExample(
            new VulnerabilityFeatures("XSS", 0.80, true, false, 7.5),
            new Label("HIGH")
        ));
        
        dataset.add(featureExtractor.createExample(
            new VulnerabilityFeatures("INSECURE_DESERIALIZATION", 0.85, true, true, 8.0),
            new Label("HIGH")
        ));
        
        // Medium severity vulnerabilities
        dataset.add(featureExtractor.createExample(
            new VulnerabilityFeatures("PATH_TRAVERSAL", 0.70, false, false, 5.5),
            new Label("MEDIUM")
        ));
        
        dataset.add(featureExtractor.createExample(
            new VulnerabilityFeatures("INFORMATION_DISCLOSURE", 0.65, false, false, 4.5),
            new Label("MEDIUM")
        ));
        
        // Low severity vulnerabilities
        dataset.add(featureExtractor.createExample(
            new VulnerabilityFeatures("DEPRECATED_API", 0.50, false, false, 2.0),
            new Label("LOW")
        ));
        
        return dataset;
    }
    
    /**
     * Evaluate model performance
     */
    private void evaluateModel(Dataset<Label> testData) {
        LabelEvaluator evaluator = new LabelEvaluator();
        LabelEvaluation evaluation = evaluator.evaluate(vulnerabilityClassifier, testData);
        
        logger.info("Model accuracy: {}", evaluation.accuracy());
        logger.info("Model confusion matrix: \n{}", evaluation.getConfusionMatrix());
    }
    
    /**
     * Calculate exploitability score
     */
    private double calculateExploitability(VulnerabilityFeatures features) {
        double score = 0.0;
        
        if (features.networkAccessible()) score += 0.4;
        if (features.authenticationRequired()) score += 0.2;
        else score += 0.4;
        
        score += features.detectionConfidence() * 0.3;
        
        return Math.min(1.0, score);
    }
    
    /**
     * Calculate impact score
     */
    private double calculateImpact(VulnerabilityFeatures features) {
        // Map vulnerability category to impact
        return switch (features.category()) {
            case "SQL_INJECTION", "REMOTE_CODE_EXECUTION" -> 1.0;
            case "XSS", "INSECURE_DESERIALIZATION" -> 0.8;
            case "PATH_TRAVERSAL", "XXE" -> 0.6;
            case "INFORMATION_DISCLOSURE" -> 0.4;
            default -> 0.2;
        };
    }
    
    /**
     * Calculate CVSS-like score
     */
    private double calculateCVSSScore(double exploitability, double impact) {
        return Math.round((exploitability * impact * 10) * 10.0) / 10.0;
    }
    
    /**
     * Check if model should be retrained
     */
    private boolean shouldRetrainModel() {
        // Retrain if we have accumulated enough new data
        return riskCache.size() > 100;
    }
    
    /**
     * Retrain model with new data
     */
    private void retrainModel() {
        logger.info("Retraining ML model with new data");
        try {
            trainOrLoadModel();
            riskCache.clear();
        } catch (Exception e) {
            logger.error("Model retraining failed", e);
        }
    }
    
    @Override
    protected void cleanup() throws Exception {
        riskCache.clear();
        logger.info("ML Classification Agent cleaned up");
    }
    
    /**
     * Vulnerability features for ML classification
     */
    record VulnerabilityFeatures(
        String category,
        double detectionConfidence,
        boolean networkAccessible,
        boolean authenticationRequired,
        double existingCVSS
    ) {}
    
    /**
     * Vulnerability risk score from ML classification
     */
    record VulnerabilityRiskScore(
        String riskLevel,
        double confidence,
        double exploitability,
        double impact,
        double cvssScore
    ) {}
    
    /**
     * Feature extractor for vulnerability data
     */
    private static class VulnerabilityFeatureExtractor {
        
        VulnerabilityFeatures extract(SecurityAgent.SecurityFinding finding) {
            return new VulnerabilityFeatures(
                finding.category(),
                finding.confidenceScore(),
                isNetworkAccessible(finding),
                requiresAuthentication(finding),
                extractCVSS(finding)
            );
        }
        
        org.tribuo.Example<Label> createExample(VulnerabilityFeatures features, Label label) {
            var example = new org.tribuo.impl.ArrayExample<>(label);
            
            // Add features
            example.add(new org.tribuo.Feature("category_" + features.category(), 1.0));
            example.add(new org.tribuo.Feature("confidence", features.detectionConfidence()));
            example.add(new org.tribuo.Feature("network_accessible", features.networkAccessible() ? 1.0 : 0.0));
            example.add(new org.tribuo.Feature("auth_required", features.authenticationRequired() ? 1.0 : 0.0));
            example.add(new org.tribuo.Feature("cvss", features.existingCVSS()));
            
            return example;
        }
        
        org.tribuo.Example<Label> createExample(VulnerabilityFeatures features, LabelFactory factory) {
            return createExample(features, new Label("UNKNOWN"));
        }
        
        private boolean isNetworkAccessible(SecurityAgent.SecurityFinding finding) {
            String desc = finding.description().toLowerCase();
            return desc.contains("network") || desc.contains("remote") || 
                   desc.contains("http") || desc.contains("api");
        }
        
        private boolean requiresAuthentication(SecurityAgent.SecurityFinding finding) {
            String desc = finding.description().toLowerCase();
            return desc.contains("authentication") || desc.contains("authorization") || 
                   desc.contains("login");
        }
        
        private double extractCVSS(SecurityAgent.SecurityFinding finding) {
            return finding.severity().getWeight() * 10.0;
        }
    }
    
    /**
     * Placeholder data source for Tribuo - removed as not needed with direct dataset creation
     */
}
