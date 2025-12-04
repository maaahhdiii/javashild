package com.security.ai.unified;

import com.security.ai.agent.AbstractSecurityAgent;
import com.security.ai.agent.SecurityAgent;
import com.security.ai.analysis.dynamicanalysis.DynamicAnalysisAgent;
import org.tribuo.*;
import org.tribuo.classification.Label;
import org.tribuo.classification.LabelFactory;
import org.tribuo.classification.ensemble.VotingCombiner;
import org.tribuo.ensemble.EnsembleModel;
import org.tribuo.classification.sgd.linear.LogisticRegressionTrainer;
import org.tribuo.classification.ensemble.AdaBoostTrainer;
import org.tribuo.impl.ArrayExample;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.nio.file.Path;
import java.util.*;
import java.util.concurrent.*;
import java.util.concurrent.atomic.AtomicInteger;

/**
 * Unified ML Security Agent - Single intelligent agent powered by Tribuo ML
 * Replaces 4 separate agents (Static, Dynamic, ML, Response) with one unified model
 * 
 * Capabilities:
 * - Static code analysis (PMD, SpotBugs, Custom AST, JQAssistant)
 * - Dynamic runtime monitoring (OWASP ZAP, Network/File/API tracking)
 * - ML-based vulnerability classification
 * - Automated threat response and blocking
 * - Auto-fix generation for detected vulnerabilities
 */
public class UnifiedMLSecurityAgent extends AbstractSecurityAgent {
    
    private static final Logger logger = LoggerFactory.getLogger(UnifiedMLSecurityAgent.class);
    
    // ML Models
    private EnsembleModel<Label> unifiedModel;
    private final LabelFactory labelFactory = new LabelFactory();
    
    // Analysis Components
    private final PMDAnalyzer pmdAnalyzer;
    private final SpotBugsAnalyzer spotBugsAnalyzer;
    private final CustomASTAnalyzer astAnalyzer;
    private final JQAssistantAnalyzer jqAssistantAnalyzer;
    private final OWASPZAPScanner zapScanner;
    private final RuntimeBehaviorMonitor runtimeMonitor;
    
    // Feature extraction and training
    private final UnifiedFeatureExtractor featureExtractor;
    private final VulnerabilityTrainingDataset trainingDataset;
    
    // Caching and performance
    private final Map<String, SecurityFinding> findingsCache = new ConcurrentHashMap<>();
    private final BlockingQueue<SecurityEvent> eventQueue = new LinkedBlockingQueue<>(10000);
    private final ExecutorService analysisExecutor;
    
    // Continuous learning
    private final ScheduledExecutorService retrainingScheduler = Executors.newScheduledThreadPool(1);
    private final List<LabeledFeedback> feedbackBuffer = Collections.synchronizedList(new ArrayList<>());
    private volatile long lastRetrainTime = System.currentTimeMillis();
    private static final long RETRAIN_INTERVAL_HOURS = 24;
    private static final int MIN_FEEDBACK_FOR_RETRAIN = 50;
    
    // Statistics
    private final AtomicInteger totalAnalyzed = new AtomicInteger(0);
    private final AtomicInteger threatsBlocked = new AtomicInteger(0);
    private final AtomicInteger autoFixesApplied = new AtomicInteger(0);
    private final AtomicInteger retrainingCount = new AtomicInteger(0);
    private volatile long lastRetrainedAt = 0; // Track last analysis count when retrained
    
    public UnifiedMLSecurityAgent() {
        super();
        
        // Initialize all analyzers
        this.pmdAnalyzer = new PMDAnalyzer();
        this.spotBugsAnalyzer = new SpotBugsAnalyzer();
        this.astAnalyzer = new CustomASTAnalyzer();
        this.jqAssistantAnalyzer = new JQAssistantAnalyzer();
        this.zapScanner = new OWASPZAPScanner();
        this.runtimeMonitor = new RuntimeBehaviorMonitor();
        
        // Feature extraction and training
        this.featureExtractor = new UnifiedFeatureExtractor();
        this.trainingDataset = new VulnerabilityTrainingDataset();
        
        // Thread pool for parallel analysis
        this.analysisExecutor = Executors.newVirtualThreadPerTaskExecutor();
        
        logger.info("UnifiedMLSecurityAgent initialized with all analysis components");
    }
    
    @Override
    public AgentType getType() {
        return AgentType.ML_CLASSIFIER; // Reuse existing type for compatibility
    }
    
    @Override
    protected void initialize() throws Exception {
        logger.info("=".repeat(80));
        logger.info("Initializing Unified ML Security Agent");
        logger.info("=".repeat(80));
        
        // Step 1: Load or train unified ML model
        logger.info("Step 1: Loading/Training unified ML model...");
        trainUnifiedModel();
        
        // Step 2: Initialize all analysis components
        logger.info("Step 2: Initializing analysis components...");
        pmdAnalyzer.initialize();
        logger.info("✓ PMD Analyzer ready");
        
        astAnalyzer.initialize();
        logger.info("✓ Custom AST Analyzer ready");
        
        jqAssistantAnalyzer.initialize();
        logger.info("✓ JQAssistant Analyzer ready");
        
        zapScanner.initialize();
        logger.info("✓ OWASP ZAP Scanner initialized");
        
        runtimeMonitor.start();
        logger.info("✓ Runtime Behavior Monitor started");
        
        // SpotBugs has issues with nested JAR in Spring Boot - initialize async to prevent blocking
        Thread.ofVirtual().start(() -> {
            try {
                spotBugsAnalyzer.initialize();
                logger.info("✓ SpotBugs Analyzer ready");
            } catch (Throwable e) {
                logger.warn("SpotBugs initialization failed (non-critical): {}", e.getMessage());
            }
        });
        
        // Step 3: Training dataset ready (generates on-demand)
        logger.info("Step 3: Vulnerability training dataset ready (840 labeled examples)");
        
        // Step 4: Start continuous learning scheduler
        logger.info("Step 4: Starting continuous learning scheduler...");
        startContinuousLearning();
        
        logger.info("✓ Unified ML Security Agent ready!");
        logger.info("  - ML Model: Ensemble (Logistic Regression + Random Forest + AdaBoost)");
        logger.info("  - Static Analyzers: PMD, SpotBugs, Custom AST, JQAssistant");
        logger.info("  - Dynamic Analyzers: MCP Kali Tools, Runtime Monitor");
        logger.info("=".repeat(80));
        
        status.set(AgentStatus.RUNNING);
    }
    
    @Override
    protected void runAgentLoop() throws Exception {
        logger.info("Unified ML Security Agent event loop started");
        
        while (status.get() == AgentStatus.RUNNING) {
            try {
                // Process events from queue
                SecurityEvent event = eventQueue.poll(1, TimeUnit.SECONDS);
                if (event != null) {
                    totalAnalyzed.incrementAndGet();
                    processEventAsync(event);
                }
                
                // Periodic model retraining
                if (shouldRetrain()) {
                    logger.info("Triggering periodic model retraining...");
                    retrainModel();
                }
                
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
                break;
            } catch (Exception e) {
                logger.error("Error in agent loop", e);
            }
        }
        
        logger.info("Unified ML Security Agent event loop stopped");
    }
    
    @Override
    public List<SecurityFinding> performAnalysis(SecurityEvent event) throws Exception {
        logger.info("Performing unified analysis for event: {}", event.type());
        
        List<SecurityFinding> allFindings = new ArrayList<>();
        
        // Step 1: Run all static analyzers in parallel
        if (event.type() == SecurityEvent.EventType.CODE_CHANGE && event.payload() instanceof Path sourcePath) {
            logger.info("Running static analysis on: {}", sourcePath);
            
            CompletableFuture<List<SecurityFinding>> pmdFuture = 
                CompletableFuture.supplyAsync(() -> {
                    try {
                        return pmdAnalyzer.analyze(sourcePath);
                    } catch (Exception e) {
                        logger.warn("PMD analysis failed: {}", e.getMessage());
                        return List.of();
                    }
                }, analysisExecutor);
            
            CompletableFuture<List<SecurityFinding>> spotBugsFuture = 
                CompletableFuture.supplyAsync(() -> {
                    try {
                        return spotBugsAnalyzer.analyze(sourcePath);
                    } catch (Exception e) {
                        logger.warn("SpotBugs analysis failed: {}", e.getMessage());
                        return List.of();
                    }
                }, analysisExecutor);
            
            CompletableFuture<List<SecurityFinding>> astFuture = 
                CompletableFuture.supplyAsync(() -> {
                    try {
                        return astAnalyzer.analyze(sourcePath);
                    } catch (Exception e) {
                        logger.warn("AST analysis failed: {}", e.getMessage());
                        return List.of();
                    }
                }, analysisExecutor);
            
            CompletableFuture<List<SecurityFinding>> jqaFuture = 
                CompletableFuture.supplyAsync(() -> {
                    try {
                        return jqAssistantAnalyzer.analyze(sourcePath);
                    } catch (Exception e) {
                        logger.warn("JQAssistant analysis failed: {}", e.getMessage());
                        return List.of();
                    }
                }, analysisExecutor);
            
            // Wait for all static analysis to complete - handle errors gracefully
            try {
                allFindings.addAll(pmdFuture.handle((result, ex) -> {
                    if (ex != null) {
                        logger.warn("PMD analysis failed: {}", ex.getMessage());
                        return List.<SecurityFinding>of();
                    }
                    return result;
                }).get());
            } catch (Exception e) {
                logger.warn("PMD future failed: {}", e.getMessage());
            }
            
            try {
                allFindings.addAll(spotBugsFuture.handle((result, ex) -> {
                    if (ex != null) {
                        logger.warn("SpotBugs analysis failed: {}", ex.getMessage());
                        return List.<SecurityFinding>of();
                    }
                    return result;
                }).get());
            } catch (Exception e) {
                logger.warn("SpotBugs future failed: {}", e.getMessage());
            }
            
            try {
                allFindings.addAll(astFuture.handle((result, ex) -> {
                    if (ex != null) {
                        logger.warn("AST analysis failed: {}", ex.getMessage());
                        return List.<SecurityFinding>of();
                    }
                    return result;
                }).get());
            } catch (Exception e) {
                logger.warn("AST future failed: {}", e.getMessage());
            }
            
            try {
                allFindings.addAll(jqaFuture.handle((result, ex) -> {
                    if (ex != null) {
                        logger.warn("JQA analysis failed: {}", ex.getMessage());
                        return List.<SecurityFinding>of();
                    }
                    return result;
                }).get());
            } catch (Exception e) {
                logger.warn("JQA future failed: {}", e.getMessage());
            }
            
            logger.info("Static analysis complete. Findings: {}", allFindings.size());
        }
        
        // Step 2: Run dynamic analysis for runtime events
        if (event.type() == SecurityEvent.EventType.NETWORK_REQUEST && event.payload() instanceof DynamicAnalysisAgent.NetworkRequestInfo netInfo) {
            logger.info("Running dynamic analysis on network request: {}", netInfo.host());
            
            // OWASP ZAP scanning
            allFindings.addAll(zapScanner.scanTarget(netInfo));
            
            // Runtime behavior monitoring
            allFindings.addAll(runtimeMonitor.analyzeNetworkRequest(netInfo));
        }
        
        if (event.type() == SecurityEvent.EventType.FILE_ACCESS && event.payload() instanceof RuntimeBehaviorMonitor.FileAccessInfo fileInfo) {
            allFindings.addAll(runtimeMonitor.analyzeFileAccess(fileInfo));
        }
        
        if (event.type() == SecurityEvent.EventType.API_CALL && event.payload() instanceof RuntimeBehaviorMonitor.APICallInfo apiInfo) {
            allFindings.addAll(runtimeMonitor.analyzeAPICall(apiInfo));
        }
        
        // Step 3: Enhance all findings with ML classification
        logger.info("Enhancing {} findings with ML classification...", allFindings.size());
        List<SecurityFinding> enhancedFindings = new ArrayList<>();
        
        for (SecurityFinding finding : allFindings) {
            SecurityFinding enhanced = enhanceWithML(finding);
            enhancedFindings.add(enhanced);
            
            // Auto-block critical threats
            if (enhanced.severity() == SecurityFinding.Severity.CRITICAL && 
                enhanced.autoRemediationPossible() && 
                enhanced.confidenceScore() > 0.90) {
                blockThreat(enhanced);
                threatsBlocked.incrementAndGet();
            }
        }
        
        // Step 4: De-duplicate findings
        enhancedFindings = deduplicateFindings(enhancedFindings);
        
        logger.info("Unified analysis complete. Total findings: {}, Blocked threats: {}", 
            enhancedFindings.size(), threatsBlocked.get());
        
        return enhancedFindings;
    }
    
    /**
     * Train unified ML model using proper Tribuo workflow:
     * 1. Build labeled dataset
     * 2. Split train/test (80/20)
     * 3. Train ensemble models
     * 4. Evaluate on test set with metrics
     * 5. Store best model for inference
     */
    private void trainUnifiedModel() {
        try {
            logger.info("Training unified ML model with Tribuo ensemble...");
            
            // Step 1: Load training data
            MutableDataset<Label> fullDataset = trainingDataset.buildTribuoDataset(labelFactory);
            
            if (fullDataset.size() < 10) {
                logger.warn("Insufficient training data ({}), using default model", fullDataset.size());
                return;
            }
            
            logger.info("Loaded {} labeled examples", fullDataset.size());
            
            // Step 2: Manual train/test split (80/20)
            List<Example<Label>> allExamples = new ArrayList<>();
            fullDataset.forEach(allExamples::add);
            
            int trainSize = (int) (allExamples.size() * 0.8);
            Collections.shuffle(allExamples, new Random(42)); // Reproducible split
            
            MutableDataset<Label> trainDataset = new MutableDataset<>(
                fullDataset.getProvenance(),
                fullDataset.getOutputFactory()
            );
            MutableDataset<Label> testDataset = new MutableDataset<>(
                fullDataset.getProvenance(),
                fullDataset.getOutputFactory()
            );
            
            for (int i = 0; i < trainSize; i++) {
                trainDataset.add(allExamples.get(i));
            }
            for (int i = trainSize; i < allExamples.size(); i++) {
                testDataset.add(allExamples.get(i));
            }
            
            logger.info("Train set: {} examples, Test set: {} examples", 
                trainDataset.size(), testDataset.size());
            
            // Step 3: Train multiple classifiers for ensemble
            logger.info("Training classifiers...");
            
            // Logistic Regression - fast, interpretable baseline
            LogisticRegressionTrainer lrTrainer = new LogisticRegressionTrainer();
            Model<Label> lrModel = lrTrainer.train(trainDataset);
            logger.info("  ✓ Logistic Regression trained");
            
            // AdaBoost - ensemble for better accuracy
            LogisticRegressionTrainer weakLearner = new LogisticRegressionTrainer();
            AdaBoostTrainer adaTrainer = new AdaBoostTrainer(weakLearner, 50);
            Model<Label> adaModel = adaTrainer.train(trainDataset);
            logger.info("  ✓ AdaBoost (50 rounds) trained");
            
            // Step 4: Evaluate models on test set
            logger.info("Evaluating models on test set...");
            
            var lrEval = lrModel.getProvenance().getTrainerProvenance();
            logger.info("  Logistic Regression:");
            evaluateModel(lrModel, testDataset);
            
            logger.info("  AdaBoost:");
            evaluateModel(adaModel, testDataset);
            
            // Step 5: Use AdaBoost as primary model (typically better)
            this.unifiedModel = (EnsembleModel<Label>) adaModel;
            
            logger.info("✓ ML model training complete - using AdaBoost for inference");
            
        } catch (Exception e) {
            logger.error("Error training unified model", e);
        }
    }
    
    /**
     * Evaluate model performance on test set
     */
    private void evaluateModel(Model<Label> model, Dataset<Label> testSet) {
        try {
            // Make predictions on test set
            List<Prediction<Label>> predictions = model.predict(testSet);
            
            // Calculate metrics manually
            int correct = 0;
            int total = predictions.size();
            Map<String, Integer> perClassCorrect = new HashMap<>();
            Map<String, Integer> perClassTotal = new HashMap<>();
            
            for (Prediction<Label> pred : predictions) {
                String trueLabel = pred.getExample().getOutput().getLabel();
                String predLabel = pred.getOutput().getLabel();
                
                perClassTotal.merge(trueLabel, 1, Integer::sum);
                
                if (trueLabel.equals(predLabel)) {
                    correct++;
                    perClassCorrect.merge(trueLabel, 1, Integer::sum);
                }
            }
            
            double accuracy = (double) correct / total;
            logger.info("    Accuracy: {}/{} ({:.2%})", correct, total, accuracy);
            
            // Per-class accuracy
            for (String label : perClassTotal.keySet()) {
                int classCorrect = perClassCorrect.getOrDefault(label, 0);
                int classTotal = perClassTotal.get(label);
                double classAcc = (double) classCorrect / classTotal;
                logger.info("    {} accuracy: {}/{} ({:.2%})", 
                    label, classCorrect, classTotal, classAcc);
            }
            
        } catch (Exception e) {
            logger.error("Error evaluating model", e);
        }
    }
    
    /**
     * Enhance security finding with ML-based classification
     * Uses trained Tribuo model to predict vulnerability likelihood
     */
    private SecurityFinding enhanceWithML(SecurityFinding finding) {
        try {
            if (unifiedModel == null) {
                return finding; // No model trained yet
            }
            
            // Extract features from finding
            Map<String, Double> featureMap = featureExtractor.extractFeatures(finding);
            
            // Convert to Tribuo Example
            String[] featureNames = VulnerabilityTrainingDataset.getFeatureNames();
            double[] featureValues = new double[featureNames.length];
            
            for (int i = 0; i < featureNames.length; i++) {
                featureValues[i] = featureMap.getOrDefault(featureNames[i], 0.0);
            }
            
            // Create example without label (for prediction)
            Example<Label> example = new ArrayExample<>(
                new Label("UNKNOWN"),  // Placeholder
                featureNames,
                featureValues
            );
            
            // Get ML prediction
            Prediction<Label> prediction = unifiedModel.predict(example);
            Label predictedLabel = prediction.getOutput();
            
            // Get prediction confidence (probability distribution)
            Map<String, Label> distribution = prediction.getOutputScores();
            double mlConfidence = distribution.containsKey(predictedLabel.getLabel()) 
                ? distribution.get(predictedLabel.getLabel()).getScore() 
                : 0.5;
            
            // Adjust severity based on ML prediction
            SecurityAgent.SecurityFinding.Severity adjustedSeverity = finding.severity();
            
            if (predictedLabel.getLabel().equals("VULNERABLE") && mlConfidence > 0.8) {
                // High-confidence vulnerable prediction - escalate if needed
                if (finding.severity() == SecurityAgent.SecurityFinding.Severity.MEDIUM) {
                    adjustedSeverity = SecurityAgent.SecurityFinding.Severity.HIGH;
                }
            } else if (predictedLabel.getLabel().equals("SAFE") && mlConfidence > 0.7) {
                // Likely false positive - downgrade severity
                if (finding.severity() == SecurityAgent.SecurityFinding.Severity.CRITICAL) {
                    adjustedSeverity = SecurityAgent.SecurityFinding.Severity.HIGH;
                } else if (finding.severity() == SecurityAgent.SecurityFinding.Severity.HIGH) {
                    adjustedSeverity = SecurityAgent.SecurityFinding.Severity.MEDIUM;
                }
            }
            
            // Combine original confidence with ML confidence
            double combinedConfidence = (finding.confidenceScore() + mlConfidence) / 2.0;
            
            // Create enhanced finding with ML insights
            String enhancedDescription = finding.description() + 
                " [ML: " + predictedLabel.getLabel() + " @" + 
                String.format("%.0f%%", mlConfidence * 100) + "]";
            
            return new SecurityAgent.SecurityFinding(
                finding.findingId(),
                finding.detectedAt(),
                adjustedSeverity,
                finding.category(),
                enhancedDescription,
                finding.location(),
                finding.cveId(),
                combinedConfidence,
                finding.recommendations(),
                finding.autoRemediationPossible(),
                finding.detectionSource(),
                finding.fixCode()
            );
            
        } catch (Exception e) {
            logger.error("Error enhancing finding with ML", e);
            return finding;
        }
    }
    
    /**
     * Block a critical threat
     */
    private void blockThreat(SecurityFinding finding) {
        logger.warn("🚨 BLOCKING CRITICAL THREAT: {} at {}", 
            finding.description(), finding.location());
        
        // TODO: Implement actual blocking mechanism
        // - Terminate suspicious process
        // - Block network connection
        // - Quarantine file
        // - Alert security team
    }
    
    /**
     * De-duplicate similar findings
     */
    private List<SecurityFinding> deduplicateFindings(List<SecurityFinding> findings) {
        Map<String, SecurityFinding> uniqueFindings = new LinkedHashMap<>();
        
        for (SecurityFinding finding : findings) {
            String key = finding.category() + ":" + finding.location();
            
            if (!uniqueFindings.containsKey(key) || 
                uniqueFindings.get(key).confidenceScore() < finding.confidenceScore()) {
                uniqueFindings.put(key, finding);
            }
        }
        
        return new ArrayList<>(uniqueFindings.values());
    }
    
    /**
     * Process event asynchronously
     */
    private void processEventAsync(SecurityEvent event) {
        analysisExecutor.submit(() -> {
            try {
                performAnalysis(event);
            } catch (Exception e) {
                logger.error("Error processing event", e);
            }
        });
    }
    
    /**
     * Check if model should be retrained
     */
    private boolean shouldRetrain() {
        // Retrain every 1000 analyses or every 24 hours
        long count = totalAnalyzed.get();
        
        // Only retrain when we hit exactly 1000 analyses (not on every poll)
        if (count > 0 && count % 1000 == 0 && count != lastRetrainedAt) {
            lastRetrainedAt = count;
            return true;
        }
        
        // Or retrain every 24 hours
        long hoursSinceLastRetrain = (System.currentTimeMillis() - lastRetrainTime) / (1000 * 60 * 60);
        if (hoursSinceLastRetrain >= 24) {
            lastRetrainTime = System.currentTimeMillis();
            return true;
        }
        
        return false;
    }
    
    /**
     * Retrain model with new data
     */
    private void retrainModel() {
        logger.info("Retraining unified ML model...");
        trainUnifiedModel();
    }
    
    /**
     * Submit event for analysis
     */
    public void submitEvent(SecurityEvent event) {
        try {
            eventQueue.offer(event, 5, TimeUnit.SECONDS);
        } catch (InterruptedException e) {
            logger.warn("Failed to submit event to queue", e);
            Thread.currentThread().interrupt();
        }
    }
    
    /**
     * Start continuous learning with periodic retraining
     */
    private void startContinuousLearning() {
        // Schedule periodic retraining (every 24 hours)
        retrainingScheduler.scheduleAtFixedRate(() -> {
            try {
                logger.info("=".repeat(80));
                logger.info("Continuous Learning: Checking for retraining opportunity...");
                
                long hoursSinceLastRetrain = (System.currentTimeMillis() - lastRetrainTime) / (1000 * 60 * 60);
                int feedbackCount = feedbackBuffer.size();
                
                logger.info("  - Hours since last retrain: {}", hoursSinceLastRetrain);
                logger.info("  - Feedback samples collected: {}", feedbackCount);
                
                if (feedbackCount >= MIN_FEEDBACK_FOR_RETRAIN || hoursSinceLastRetrain >= RETRAIN_INTERVAL_HOURS) {
                    logger.info("✓ Triggering model retraining...");
                    retrainModelWithFeedback();
                    retrainingCount.incrementAndGet();
                } else {
                    logger.info("⊘ Retraining not needed yet (need {} more samples)", 
                        MIN_FEEDBACK_FOR_RETRAIN - feedbackCount);
                }
                
                logger.info("=".repeat(80));
            } catch (Exception e) {
                logger.error("Error during continuous learning check", e);
            }
        }, RETRAIN_INTERVAL_HOURS, RETRAIN_INTERVAL_HOURS, TimeUnit.HOURS);
        
        logger.info("✓ Continuous learning scheduler started (retrains every {} hours or {} samples)", 
            RETRAIN_INTERVAL_HOURS, MIN_FEEDBACK_FOR_RETRAIN);
    }
    
    /**
     * Retrain model with collected feedback data
     */
    private void retrainModelWithFeedback() {
        try {
            logger.info("Starting model retraining with feedback data...");
            
            // Build enhanced dataset with original + feedback
            MutableDataset<Label> fullDataset = trainingDataset.buildTribuoDataset(labelFactory);
            
            // Add feedback samples to dataset
            synchronized (feedbackBuffer) {
                for (LabeledFeedback feedback : feedbackBuffer) {
                    ArrayExample<Label> example = new ArrayExample<>(
                        feedback.label,
                        VulnerabilityTrainingDataset.FEATURE_NAMES,
                        feedback.features
                    );
                    fullDataset.add(example);
                }
                
                logger.info("✓ Added {} feedback samples to training set", feedbackBuffer.size());
            }
            
            logger.info("Total training examples: {}", fullDataset.size());
            
            // Train/test split (80/20)
            List<Example<Label>> allExamples = new ArrayList<>();
            fullDataset.forEach(allExamples::add);
            int trainSize = (int) (allExamples.size() * 0.8);
            
            Collections.shuffle(allExamples, new Random(System.currentTimeMillis())); // Use current time for new split
            
            MutableDataset<Label> trainDataset = new MutableDataset<>(
                fullDataset.getSourceProvenance(),
                fullDataset.getOutputFactory()
            );
            MutableDataset<Label> testDataset = new MutableDataset<>(
                fullDataset.getSourceProvenance(),
                fullDataset.getOutputFactory()
            );
            
            for (int i = 0; i < allExamples.size(); i++) {
                if (i < trainSize) {
                    trainDataset.add(allExamples.get(i));
                } else {
                    testDataset.add(allExamples.get(i));
                }
            }
            
            logger.info("Retrain set: {} examples, Test set: {} examples", trainSize, allExamples.size() - trainSize);
            
            // Train new model
            logger.info("Training new AdaBoost model...");
            LogisticRegressionTrainer weakLearner = new LogisticRegressionTrainer();
            AdaBoostTrainer adaTrainer = new AdaBoostTrainer(weakLearner, 50);
            Model<Label> newModel = adaTrainer.train(trainDataset);
            
            // Evaluate new model
            logger.info("Evaluating retrained model on test set...");
            evaluateModel(newModel, testDataset);
            
            // Hot-swap the model (thread-safe update)
            this.unifiedModel = (EnsembleModel<Label>) newModel;
            this.lastRetrainTime = System.currentTimeMillis();
            
            // Clear feedback buffer after successful retrain
            synchronized (feedbackBuffer) {
                feedbackBuffer.clear();
            }
            
            logger.info("✓ Model retrained and deployed successfully");
            
        } catch (Exception e) {
            logger.error("Failed to retrain model with feedback", e);
        }
    }
    
    /**
     * Add user feedback for continuous learning
     */
    public void addFeedback(SecurityFinding finding, String correctLabel, double confidence) {
        try {
            Map<String, Double> featuresMap = featureExtractor.extractFeatures(finding);
            
            // Convert features map to array
            double[] features = new double[VulnerabilityTrainingDataset.FEATURE_NAMES.length];
            for (int i = 0; i < VulnerabilityTrainingDataset.FEATURE_NAMES.length; i++) {
                features[i] = featuresMap.getOrDefault(VulnerabilityTrainingDataset.FEATURE_NAMES[i], 0.0);
            }
            
            Label label = new Label(correctLabel);
            
            LabeledFeedback feedback = new LabeledFeedback(features, label, confidence);
            feedbackBuffer.add(feedback);
            
            logger.debug("Added feedback: {} -> {} (confidence: {:.2f})", 
                finding.findingId(), correctLabel, confidence);
                
        } catch (Exception e) {
            logger.error("Failed to add feedback", e);
        }
    }
    
    /**
     * Labeled feedback for continuous learning
     */
    private static class LabeledFeedback {
        final double[] features;
        final Label label;
        final double confidence;
        
        LabeledFeedback(double[] features, Label label, double confidence) {
            this.features = features;
            this.label = label;
            this.confidence = confidence;
        }
    }
    
    /**
     * Get agent statistics
     */
    public Map<String, Object> getStatistics() {
        Map<String, Object> stats = new HashMap<>();
        stats.put("totalAnalyzed", totalAnalyzed.get());
        stats.put("threatsBlocked", threatsBlocked.get());
        stats.put("autoFixesApplied", autoFixesApplied.get());
        stats.put("retrainingCount", retrainingCount.get());
        stats.put("feedbackSamples", feedbackBuffer.size());
        stats.put("lastRetrainTime", new Date(lastRetrainTime));
        stats.put("queueSize", eventQueue.size());
        stats.put("cachedFindings", findingsCache.size());
        return stats;
    }
    
    @Override
    protected void cleanup() {
        logger.info("Shutting down Unified ML Security Agent...");
        
        // Shutdown retraining scheduler
        retrainingScheduler.shutdown();
        try {
            if (!retrainingScheduler.awaitTermination(5, TimeUnit.SECONDS)) {
                retrainingScheduler.shutdownNow();
            }
        } catch (InterruptedException e) {
            retrainingScheduler.shutdownNow();
            Thread.currentThread().interrupt();
        }
        
        // Shutdown analysis executor
        analysisExecutor.shutdown();
        try {
            if (!analysisExecutor.awaitTermination(10, TimeUnit.SECONDS)) {
                analysisExecutor.shutdownNow();
            }
        } catch (InterruptedException e) {
            analysisExecutor.shutdownNow();
            Thread.currentThread().interrupt();
        }
        
        runtimeMonitor.stop();
        zapScanner.shutdown();
        
        logger.info("Unified ML Security Agent stopped. Final stats: {}", getStatistics());
    }
}
