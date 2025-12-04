package com.security.ai.unified;

import org.deeplearning4j.nn.conf.MultiLayerConfiguration;
import org.deeplearning4j.nn.conf.NeuralNetConfiguration;
import org.deeplearning4j.nn.conf.layers.DenseLayer;
import org.deeplearning4j.nn.conf.layers.OutputLayer;
import org.deeplearning4j.nn.multilayer.MultiLayerNetwork;
import org.deeplearning4j.nn.weights.WeightInit;
import org.deeplearning4j.optimize.listeners.ScoreIterationListener;
import org.nd4j.linalg.activations.Activation;
import org.nd4j.linalg.api.ndarray.INDArray;
import org.nd4j.linalg.dataset.DataSet;
import org.nd4j.linalg.dataset.api.iterator.DataSetIterator;
import org.nd4j.linalg.dataset.api.preprocessor.DataNormalization;
import org.nd4j.linalg.dataset.api.preprocessor.NormalizerStandardize;
import org.nd4j.linalg.factory.Nd4j;
import org.nd4j.linalg.learning.config.Adam;
import org.nd4j.linalg.lossfunctions.LossFunctions;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.File;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.*;
import java.util.concurrent.ConcurrentHashMap;
import java.util.regex.Pattern;

/**
 * Deep Learning Security Model using Deeplearning4j
 * 
 * Neural Network Architecture:
 * - Input Layer: Code features (patterns, tokens, metrics)
 * - Hidden Layer 1: 256 neurons (ReLU activation)
 * - Hidden Layer 2: 128 neurons (ReLU activation)
 * - Hidden Layer 3: 64 neurons (ReLU activation)
 * - Output Layer: 4 classes (SAFE, LOW, MEDIUM, HIGH/CRITICAL)
 * 
 * Features extracted from code:
 * - Lexical features (token frequencies, string patterns)
 * - Structural features (nesting depth, complexity)
 * - Security patterns (known vulnerability signatures)
 * - Semantic features (API usage, data flow indicators)
 */
public class DeepLearningSecurityModel {
    
    private static final Logger logger = LoggerFactory.getLogger(DeepLearningSecurityModel.class);
    
    // Neural network configuration
    private static final int INPUT_FEATURES = 150;  // Number of input features
    private static final int HIDDEN_LAYER_1 = 256;
    private static final int HIDDEN_LAYER_2 = 128;
    private static final int HIDDEN_LAYER_3 = 64;
    private static final int OUTPUT_CLASSES = 4;    // SAFE, LOW, MEDIUM, HIGH
    
    private static final int EPOCHS = 100;
    private static final int BATCH_SIZE = 32;
    private static final double LEARNING_RATE = 0.001;
    
    private MultiLayerNetwork model;
    private DataNormalization normalizer;
    private boolean isTrained = false;
    
    // Feature extraction patterns
    private final Map<String, Pattern> securityPatterns = new ConcurrentHashMap<>();
    private final Map<String, Integer> tokenVocabulary = new ConcurrentHashMap<>();
    
    // Training data
    private final List<double[]> trainingFeatures = new ArrayList<>();
    private final List<Integer> trainingLabels = new ArrayList<>();
    
    public DeepLearningSecurityModel() {
        initializePatterns();
        initializeVocabulary();
    }
    
    /**
     * Initialize the neural network architecture
     */
    public void initialize() {
        logger.info("Initializing Deep Learning Security Model (DL4J)...");
        
        try {
            MultiLayerConfiguration config = new NeuralNetConfiguration.Builder()
                .seed(42)
                .weightInit(WeightInit.XAVIER)
                .updater(new Adam(LEARNING_RATE))
                .l2(0.0001)  // L2 regularization
                .list()
                // Hidden Layer 1
                .layer(0, new DenseLayer.Builder()
                    .nIn(INPUT_FEATURES)
                    .nOut(HIDDEN_LAYER_1)
                    .activation(Activation.RELU)
                    .dropOut(0.2)
                    .build())
                // Hidden Layer 2
                .layer(1, new DenseLayer.Builder()
                    .nIn(HIDDEN_LAYER_1)
                    .nOut(HIDDEN_LAYER_2)
                    .activation(Activation.RELU)
                    .dropOut(0.2)
                    .build())
                // Hidden Layer 3
                .layer(2, new DenseLayer.Builder()
                    .nIn(HIDDEN_LAYER_2)
                    .nOut(HIDDEN_LAYER_3)
                    .activation(Activation.RELU)
                    .dropOut(0.1)
                    .build())
                // Output Layer
                .layer(3, new OutputLayer.Builder(LossFunctions.LossFunction.NEGATIVELOGLIKELIHOOD)
                    .nIn(HIDDEN_LAYER_3)
                    .nOut(OUTPUT_CLASSES)
                    .activation(Activation.SOFTMAX)
                    .build())
                .build();
            
            model = new MultiLayerNetwork(config);
            model.init();
            model.setListeners(new ScoreIterationListener(50));
            
            normalizer = new NormalizerStandardize();
            
            logger.info("✓ DL4J Neural Network initialized:");
            logger.info("  - Architecture: {} → {} → {} → {} → {}", 
                INPUT_FEATURES, HIDDEN_LAYER_1, HIDDEN_LAYER_2, HIDDEN_LAYER_3, OUTPUT_CLASSES);
            logger.info("  - Parameters: {}", model.numParams());
            logger.info("  - Optimizer: Adam (lr={})", LEARNING_RATE);
            
        } catch (Exception e) {
            logger.error("Failed to initialize DL4J model: {}", e.getMessage(), e);
        }
    }
    
    /**
     * Load pre-built training data and train the model
     */
    public void trainModel() {
        logger.info("Training Deep Learning model...");
        
        try {
            // Load training data from VulnerabilityTrainingDataset patterns
            loadTrainingData();
            
            if (trainingFeatures.isEmpty()) {
                logger.warn("No training data available");
                return;
            }
            
            // Convert to ND4J arrays
            int numSamples = trainingFeatures.size();
            INDArray features = Nd4j.create(numSamples, INPUT_FEATURES);
            INDArray labels = Nd4j.zeros(numSamples, OUTPUT_CLASSES);
            
            for (int i = 0; i < numSamples; i++) {
                features.putRow(i, Nd4j.create(trainingFeatures.get(i)));
                labels.putScalar(new int[]{i, trainingLabels.get(i)}, 1.0);
            }
            
            DataSet dataSet = new DataSet(features, labels);
            
            // Normalize features
            normalizer.fit(dataSet);
            normalizer.transform(dataSet);
            
            // Split into train/test (80/20)
            dataSet.shuffle(42);
            List<DataSet> splits = dataSet.asList();
            int trainSize = (int) (splits.size() * 0.8);
            
            List<DataSet> trainList = splits.subList(0, trainSize);
            List<DataSet> testList = splits.subList(trainSize, splits.size());
            
            DataSet trainData = DataSet.merge(trainList);
            DataSet testData = DataSet.merge(testList);
            
            logger.info("Training on {} samples, testing on {} samples", trainSize, splits.size() - trainSize);
            
            // Train the model
            for (int epoch = 0; epoch < EPOCHS; epoch++) {
                model.fit(trainData);
                
                if (epoch % 20 == 0 || epoch == EPOCHS - 1) {
                    // Evaluate on test set
                    INDArray output = model.output(testData.getFeatures());
                    double accuracy = calculateAccuracy(output, testData.getLabels());
                    logger.info("  Epoch {}/{}: Test Accuracy = {:.2f}%", epoch + 1, EPOCHS, accuracy * 100);
                }
            }
            
            // Final evaluation
            INDArray testOutput = model.output(testData.getFeatures());
            double finalAccuracy = calculateAccuracy(testOutput, testData.getLabels());
            
            logger.info("✓ DL4J Training complete!");
            logger.info("  - Final Test Accuracy: {:.2f}%", finalAccuracy * 100);
            logger.info("  - Model ready for inference");
            
            isTrained = true;
            
        } catch (Exception e) {
            logger.error("Failed to train DL4J model: {}", e.getMessage(), e);
        }
    }
    
    /**
     * Classify a code snippet using the deep learning model
     */
    public SecurityPrediction classify(String code) {
        if (!isTrained || model == null) {
            return new SecurityPrediction("UNKNOWN", 0.0, new double[OUTPUT_CLASSES]);
        }
        
        try {
            // Extract features from code
            double[] features = extractFeatures(code);
            
            // Create input array
            INDArray input = Nd4j.create(new double[][]{features});
            
            // Normalize
            normalizer.transform(input);
            
            // Get prediction
            INDArray output = model.output(input);
            double[] probabilities = output.toDoubleVector();
            
            // Find highest probability class
            int predictedClass = 0;
            double maxProb = probabilities[0];
            for (int i = 1; i < probabilities.length; i++) {
                if (probabilities[i] > maxProb) {
                    maxProb = probabilities[i];
                    predictedClass = i;
                }
            }
            
            String label = switch (predictedClass) {
                case 0 -> "SAFE";
                case 1 -> "LOW";
                case 2 -> "MEDIUM";
                case 3 -> "HIGH";
                default -> "UNKNOWN";
            };
            
            return new SecurityPrediction(label, maxProb, probabilities);
            
        } catch (Exception e) {
            logger.error("Prediction failed: {}", e.getMessage());
            return new SecurityPrediction("UNKNOWN", 0.0, new double[OUTPUT_CLASSES]);
        }
    }
    
    /**
     * Extract features from code for the neural network
     */
    public double[] extractFeatures(String code) {
        double[] features = new double[INPUT_FEATURES];
        int idx = 0;
        
        // ===== Lexical Features (50 features) =====
        String codeLower = code.toLowerCase();
        
        // Token frequencies (top 30 security-relevant tokens)
        String[] securityTokens = {
            "password", "secret", "key", "token", "auth", "login", "admin",
            "select", "insert", "update", "delete", "from", "where", "exec",
            "eval", "system", "runtime", "process", "command", "shell",
            "file", "path", "read", "write", "open", "close", "stream",
            "http", "https", "url", "socket"
        };
        
        for (int i = 0; i < Math.min(30, securityTokens.length); i++) {
            features[idx++] = countOccurrences(codeLower, securityTokens[i]);
        }
        
        // Character type ratios (5 features)
        features[idx++] = countMatches(code, "[a-zA-Z]") / (double) Math.max(1, code.length());
        features[idx++] = countMatches(code, "[0-9]") / (double) Math.max(1, code.length());
        features[idx++] = countMatches(code, "[^a-zA-Z0-9\\s]") / (double) Math.max(1, code.length());
        features[idx++] = countMatches(code, "\\s") / (double) Math.max(1, code.length());
        features[idx++] = countMatches(code, "\"") / (double) Math.max(1, code.length());
        
        // String literal analysis (5 features)
        int stringCount = countMatches(code, "\"[^\"]*\"");
        int longStrings = countMatches(code, "\"[^\"]{20,}\"");
        features[idx++] = stringCount;
        features[idx++] = longStrings;
        features[idx++] = countMatches(code, "http://");
        features[idx++] = countMatches(code, "https://");
        features[idx++] = countMatches(code, "\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}");
        
        // Comment analysis (5 features)
        features[idx++] = countMatches(code, "//.*");
        features[idx++] = countMatches(code, "/\\*");
        features[idx++] = countOccurrences(codeLower, "todo");
        features[idx++] = countOccurrences(codeLower, "fixme");
        features[idx++] = countOccurrences(codeLower, "hack");
        
        // ===== Structural Features (30 features) =====
        
        // Nesting and complexity
        features[idx++] = countMatches(code, "\\{");
        features[idx++] = countMatches(code, "\\}");
        features[idx++] = countMatches(code, "\\(");
        features[idx++] = countMatches(code, "\\)");
        features[idx++] = countMatches(code, "\\[");
        features[idx++] = countMatches(code, "\\]");
        
        // Control flow
        features[idx++] = countOccurrences(codeLower, "if");
        features[idx++] = countOccurrences(codeLower, "else");
        features[idx++] = countOccurrences(codeLower, "for");
        features[idx++] = countOccurrences(codeLower, "while");
        features[idx++] = countOccurrences(codeLower, "switch");
        features[idx++] = countOccurrences(codeLower, "case");
        features[idx++] = countOccurrences(codeLower, "try");
        features[idx++] = countOccurrences(codeLower, "catch");
        features[idx++] = countOccurrences(codeLower, "throw");
        
        // Method/class structure
        features[idx++] = countOccurrences(codeLower, "public");
        features[idx++] = countOccurrences(codeLower, "private");
        features[idx++] = countOccurrences(codeLower, "protected");
        features[idx++] = countOccurrences(codeLower, "static");
        features[idx++] = countOccurrences(codeLower, "final");
        features[idx++] = countOccurrences(codeLower, "class");
        features[idx++] = countOccurrences(codeLower, "interface");
        features[idx++] = countOccurrences(codeLower, "extends");
        features[idx++] = countOccurrences(codeLower, "implements");
        
        // Line statistics
        String[] lines = code.split("\n");
        features[idx++] = lines.length;
        features[idx++] = Arrays.stream(lines).mapToInt(String::length).average().orElse(0);
        features[idx++] = Arrays.stream(lines).mapToInt(String::length).max().orElse(0);
        features[idx++] = countEmptyLines(lines);
        features[idx++] = countMatches(code, ";");
        
        // ===== Security Pattern Features (50 features) =====
        
        // SQL Injection indicators
        features[idx++] = countOccurrences(codeLower, "executequery");
        features[idx++] = countOccurrences(codeLower, "executeupdate");
        features[idx++] = countOccurrences(codeLower, "preparedstatement");
        features[idx++] = countOccurrences(codeLower, "statement");
        features[idx++] = countMatches(code, "\\+.*['\"].*SELECT|INSERT|UPDATE|DELETE");
        
        // XSS indicators
        features[idx++] = countOccurrences(codeLower, "innerhtml");
        features[idx++] = countOccurrences(codeLower, "document.write");
        features[idx++] = countOccurrences(codeLower, "getparameter");
        features[idx++] = countOccurrences(codeLower, "response.getwriter");
        features[idx++] = countMatches(code, "<script");
        
        // Command injection
        features[idx++] = countOccurrences(codeLower, "runtime.getruntime");
        features[idx++] = countOccurrences(codeLower, "processbuilder");
        features[idx++] = countOccurrences(codeLower, ".exec(");
        features[idx++] = countMatches(code, "cmd|bash|sh|powershell");
        
        // Cryptography
        features[idx++] = countOccurrences(codeLower, "md5");
        features[idx++] = countOccurrences(codeLower, "sha1");
        features[idx++] = countOccurrences(codeLower, "sha256");
        features[idx++] = countOccurrences(codeLower, "aes");
        features[idx++] = countOccurrences(codeLower, "des");
        features[idx++] = countOccurrences(codeLower, "cipher");
        features[idx++] = countOccurrences(codeLower, "secretkey");
        features[idx++] = countOccurrences(codeLower, "securerandom");
        features[idx++] = countMatches(code, "new Random\\(");
        
        // File operations
        features[idx++] = countOccurrences(codeLower, "fileinputstream");
        features[idx++] = countOccurrences(codeLower, "fileoutputstream");
        features[idx++] = countOccurrences(codeLower, "bufferedreader");
        features[idx++] = countOccurrences(codeLower, "files.read");
        features[idx++] = countOccurrences(codeLower, "files.write");
        
        // Deserialization
        features[idx++] = countOccurrences(codeLower, "objectinputstream");
        features[idx++] = countOccurrences(codeLower, "readobject");
        features[idx++] = countOccurrences(codeLower, "serializable");
        
        // XML/XXE
        features[idx++] = countOccurrences(codeLower, "documentbuilderfactory");
        features[idx++] = countOccurrences(codeLower, "saxparser");
        features[idx++] = countOccurrences(codeLower, "xmlreader");
        features[idx++] = countOccurrences(codeLower, "setfeature");
        
        // Network
        features[idx++] = countOccurrences(codeLower, "socket");
        features[idx++] = countOccurrences(codeLower, "serversocket");
        features[idx++] = countOccurrences(codeLower, "httpurlconnection");
        features[idx++] = countOccurrences(codeLower, "httpclient");
        features[idx++] = countOccurrences(codeLower, "sslcontext");
        
        // LDAP
        features[idx++] = countOccurrences(codeLower, "ldap");
        features[idx++] = countOccurrences(codeLower, "dircontext");
        
        // ===== Semantic Features (20 features) =====
        
        // Data flow indicators
        features[idx++] = countOccurrences(codeLower, "request");
        features[idx++] = countOccurrences(codeLower, "response");
        features[idx++] = countOccurrences(codeLower, "session");
        features[idx++] = countOccurrences(codeLower, "cookie");
        features[idx++] = countOccurrences(codeLower, "header");
        
        // Input handling
        features[idx++] = countOccurrences(codeLower, "scanner");
        features[idx++] = countOccurrences(codeLower, "readline");
        features[idx++] = countOccurrences(codeLower, "input");
        features[idx++] = countOccurrences(codeLower, "args");
        
        // Output handling
        features[idx++] = countOccurrences(codeLower, "print");
        features[idx++] = countOccurrences(codeLower, "logger");
        features[idx++] = countOccurrences(codeLower, "log.");
        
        // Validation patterns
        features[idx++] = countOccurrences(codeLower, "validate");
        features[idx++] = countOccurrences(codeLower, "sanitize");
        features[idx++] = countOccurrences(codeLower, "escape");
        features[idx++] = countOccurrences(codeLower, "encode");
        features[idx++] = countOccurrences(codeLower, "filter");
        
        // Fill remaining with zeros if needed
        while (idx < INPUT_FEATURES) {
            features[idx++] = 0;
        }
        
        return features;
    }
    
    /**
     * Load training data from vulnerability patterns
     */
    private void loadTrainingData() {
        logger.info("Loading training data for Deep Learning model...");
        
        // SQL Injection examples (Label: 3 = HIGH)
        addTrainingExample("String query = \"SELECT * FROM users WHERE id=\" + userId; stmt.executeQuery(query);", 3);
        addTrainingExample("connection.createStatement().execute(\"DELETE FROM \" + table);", 3);
        addTrainingExample("String sql = \"INSERT INTO logs VALUES('\" + userInput + \"')\";", 3);
        
        // Prepared statement (Label: 0 = SAFE)
        addTrainingExample("PreparedStatement ps = conn.prepareStatement(\"SELECT * FROM users WHERE id=?\"); ps.setInt(1, id);", 0);
        addTrainingExample("pstmt.setString(1, username); ResultSet rs = pstmt.executeQuery();", 0);
        
        // Hardcoded credentials (Label: 3 = HIGH)
        addTrainingExample("String password = \"admin123\"; String apiKey = \"sk-secret-key-12345\";", 3);
        addTrainingExample("private static final String DB_PASSWORD = \"root\";", 3);
        addTrainingExample("String secret = \"mysupersecretpassword\";", 3);
        
        // Environment variables (Label: 0 = SAFE)
        addTrainingExample("String password = System.getenv(\"DB_PASSWORD\");", 0);
        addTrainingExample("String apiKey = config.getProperty(\"api.key\");", 0);
        
        // Command injection (Label: 3 = HIGH)
        addTrainingExample("Runtime.getRuntime().exec(\"cmd /c \" + userInput);", 3);
        addTrainingExample("Process p = Runtime.getRuntime().exec(command + args);", 3);
        addTrainingExample("ProcessBuilder pb = new ProcessBuilder(\"sh\", \"-c\", input);", 3);
        
        // Safe command execution (Label: 1 = LOW)
        addTrainingExample("ProcessBuilder pb = new ProcessBuilder(\"ls\", \"-la\"); pb.start();", 1);
        
        // XSS (Label: 3 = HIGH)
        addTrainingExample("response.getWriter().print(request.getParameter(\"name\"));", 3);
        addTrainingExample("out.println(\"<div>\" + userInput + \"</div>\");", 3);
        addTrainingExample("document.innerHTML = userData;", 3);
        
        // Sanitized output (Label: 0 = SAFE)
        addTrainingExample("String safe = StringEscapeUtils.escapeHtml4(input); out.print(safe);", 0);
        addTrainingExample("response.getWriter().print(HtmlUtils.htmlEscape(data));", 0);
        
        // Weak crypto (Label: 2 = MEDIUM)
        addTrainingExample("MessageDigest md = MessageDigest.getInstance(\"MD5\");", 2);
        addTrainingExample("MessageDigest.getInstance(\"SHA-1\");", 2);
        addTrainingExample("Cipher.getInstance(\"DES\");", 2);
        addTrainingExample("Cipher cipher = Cipher.getInstance(\"AES/ECB/PKCS5Padding\");", 2);
        
        // Strong crypto (Label: 0 = SAFE)
        addTrainingExample("MessageDigest md = MessageDigest.getInstance(\"SHA-256\");", 0);
        addTrainingExample("Cipher cipher = Cipher.getInstance(\"AES/GCM/NoPadding\");", 0);
        addTrainingExample("SecureRandom random = new SecureRandom();", 0);
        
        // Weak random (Label: 2 = MEDIUM)
        addTrainingExample("Random rand = new Random(); int token = rand.nextInt();", 2);
        addTrainingExample("double value = Math.random();", 2);
        
        // Deserialization (Label: 3 = HIGH)
        addTrainingExample("ObjectInputStream ois = new ObjectInputStream(input); Object obj = ois.readObject();", 3);
        addTrainingExample("new ObjectInputStream(socket.getInputStream()).readObject();", 3);
        
        // Safe deserialization (Label: 0 = SAFE)
        addTrainingExample("ObjectMapper mapper = new ObjectMapper(); User user = mapper.readValue(json, User.class);", 0);
        addTrainingExample("Gson gson = new Gson(); Data data = gson.fromJson(jsonString, Data.class);", 0);
        
        // XXE (Label: 3 = HIGH)
        addTrainingExample("DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance(); dbf.newDocumentBuilder().parse(input);", 3);
        addTrainingExample("SAXParserFactory.newInstance().newSAXParser().parse(xmlFile, handler);", 3);
        
        // Safe XML (Label: 0 = SAFE)
        addTrainingExample("dbf.setFeature(XMLConstants.FEATURE_SECURE_PROCESSING, true); dbf.setFeature(\"http://apache.org/xml/features/disallow-doctype-decl\", true);", 0);
        
        // Path traversal (Label: 3 = HIGH)
        addTrainingExample("File file = new File(\"/uploads/\" + request.getParameter(\"file\"));", 3);
        addTrainingExample("FileInputStream fis = new FileInputStream(basePath + userInput);", 3);
        
        // Safe file access (Label: 0 = SAFE)
        addTrainingExample("Path path = Paths.get(basePath).resolve(filename).normalize(); if(path.startsWith(basePath)) { Files.read(path); }", 0);
        
        // LDAP injection (Label: 3 = HIGH)
        addTrainingExample("ctx.search(\"ou=users\", \"(uid=\" + username + \")\", null);", 3);
        
        // Insecure HTTP (Label: 2 = MEDIUM)
        addTrainingExample("URL url = new URL(\"http://api.example.com/data\");", 2);
        addTrainingExample("HttpURLConnection conn = (HttpURLConnection) url.openConnection();", 1);
        
        // Secure HTTPS (Label: 0 = SAFE)
        addTrainingExample("URL url = new URL(\"https://api.example.com/data\");", 0);
        
        // SSL/TLS issues (Label: 3 = HIGH)
        addTrainingExample("TrustManager[] trustAll = new TrustManager[] { new X509TrustManager() { public void checkClientTrusted() {} }};", 3);
        addTrainingExample("HostnameVerifier allHosts = (hostname, session) -> true;", 3);
        
        // Empty catch (Label: 1 = LOW)
        addTrainingExample("try { riskyOperation(); } catch (Exception e) { }", 1);
        addTrainingExample("catch (SQLException e) { // ignore }", 1);
        
        // Proper exception handling (Label: 0 = SAFE)
        addTrainingExample("catch (Exception e) { logger.error(\"Error occurred\", e); throw new RuntimeException(e); }", 0);
        
        // Logging sensitive data (Label: 2 = MEDIUM)
        addTrainingExample("logger.info(\"User password: \" + password);", 2);
        addTrainingExample("log.debug(\"API Key: \" + apiKey);", 2);
        
        // Safe logging (Label: 0 = SAFE)
        addTrainingExample("logger.info(\"User {} logged in\", username);", 0);
        
        // Generate variations to increase dataset size
        generateVariations();
        
        logger.info("Loaded {} training examples", trainingFeatures.size());
    }
    
    private void addTrainingExample(String code, int label) {
        double[] features = extractFeatures(code);
        trainingFeatures.add(features);
        trainingLabels.add(label);
    }
    
    private void generateVariations() {
        // Create variations of existing examples
        int originalSize = trainingFeatures.size();
        
        for (int i = 0; i < originalSize; i++) {
            double[] original = trainingFeatures.get(i);
            int label = trainingLabels.get(i);
            
            // Add noise variations
            for (int v = 0; v < 5; v++) {
                double[] variation = new double[original.length];
                Random rand = new Random(i * 100 + v);
                for (int j = 0; j < original.length; j++) {
                    variation[j] = original[j] + (rand.nextGaussian() * 0.1 * Math.max(1, original[j]));
                    variation[j] = Math.max(0, variation[j]);
                }
                trainingFeatures.add(variation);
                trainingLabels.add(label);
            }
        }
    }
    
    private void initializePatterns() {
        securityPatterns.put("SQL_INJECTION", Pattern.compile("executeQuery|executeUpdate|createStatement", Pattern.CASE_INSENSITIVE));
        securityPatterns.put("XSS", Pattern.compile("innerHTML|document\\.write|getParameter", Pattern.CASE_INSENSITIVE));
        securityPatterns.put("COMMAND_INJECTION", Pattern.compile("Runtime\\.getRuntime|ProcessBuilder|exec\\(", Pattern.CASE_INSENSITIVE));
        securityPatterns.put("WEAK_CRYPTO", Pattern.compile("MD5|SHA-?1|DES|RC4", Pattern.CASE_INSENSITIVE));
    }
    
    private void initializeVocabulary() {
        String[] tokens = {"password", "secret", "key", "token", "query", "exec", "eval", "file", "path", "url"};
        for (int i = 0; i < tokens.length; i++) {
            tokenVocabulary.put(tokens[i], i);
        }
    }
    
    private int countOccurrences(String text, String word) {
        int count = 0;
        int index = 0;
        while ((index = text.indexOf(word, index)) != -1) {
            count++;
            index += word.length();
        }
        return count;
    }
    
    private int countMatches(String text, String regex) {
        try {
            java.util.regex.Matcher matcher = Pattern.compile(regex).matcher(text);
            int count = 0;
            while (matcher.find()) count++;
            return count;
        } catch (Exception e) {
            return 0;
        }
    }
    
    private int countEmptyLines(String[] lines) {
        int count = 0;
        for (String line : lines) {
            if (line.trim().isEmpty()) count++;
        }
        return count;
    }
    
    private double calculateAccuracy(INDArray predictions, INDArray labels) {
        int correct = 0;
        int total = (int) predictions.rows();
        
        for (int i = 0; i < total; i++) {
            int predicted = Nd4j.argMax(predictions.getRow(i)).getInt(0);
            int actual = Nd4j.argMax(labels.getRow(i)).getInt(0);
            if (predicted == actual) correct++;
        }
        
        return (double) correct / total;
    }
    
    /**
     * Save model to file
     */
    public void saveModel(Path path) throws IOException {
        if (model != null) {
            model.save(path.toFile());
            logger.info("Model saved to: {}", path);
        }
    }
    
    /**
     * Load model from file
     */
    public void loadModel(Path path) throws IOException {
        if (Files.exists(path)) {
            model = MultiLayerNetwork.load(path.toFile(), true);
            isTrained = true;
            logger.info("Model loaded from: {}", path);
        }
    }
    
    public boolean isTrained() {
        return isTrained;
    }
    
    /**
     * Alias for isTrained() - used by controller
     */
    public boolean isModelTrained() {
        return isTrained;
    }
    
    /**
     * Get model information summary
     */
    public String getModelInfo() {
        if (model == null) {
            return "Model not initialized";
        }
        return String.format("DL4J Neural Network [%d→%d→%d→%d→%d] - %d params - %s",
            INPUT_FEATURES, HIDDEN_LAYER_1, HIDDEN_LAYER_2, HIDDEN_LAYER_3, OUTPUT_CLASSES,
            model.numParams(), isTrained ? "TRAINED" : "NOT TRAINED");
    }
    
    /**
     * Predict vulnerability for code snippet (wrapper for classify)
     */
    public DLPrediction predict(String code) {
        SecurityPrediction prediction = classify(code);
        return new DLPrediction(prediction.label(), prediction.confidence());
    }
    
    /**
     * Train model with labeled code snippets
     */
    public void train(List<String> codeSnippets, List<String> labels) {
        logger.info("Training DL4J model with {} labeled samples...", codeSnippets.size());
        
        trainingFeatures.clear();
        trainingLabels.clear();
        
        for (int i = 0; i < codeSnippets.size(); i++) {
            String code = codeSnippets.get(i);
            String label = labels.get(i);
            
            int labelIdx = switch (label.toUpperCase()) {
                case "VULNERABLE", "HIGH" -> 3;
                case "SUSPICIOUS", "MEDIUM" -> 2;
                case "LOW" -> 1;
                default -> 0; // SAFE
            };
            
            addTrainingExample(code, labelIdx);
        }
        
        // Generate variations and train
        generateVariations();
        trainModel();
    }
    
    /**
     * DL Prediction result for compatibility with agent
     */
    public record DLPrediction(String classification, double confidence) {}
    
    /**
     * Security prediction result
     */
    public record SecurityPrediction(
        String label,
        double confidence,
        double[] classProbabilities
    ) {
        public String getSummary() {
            return String.format("%s (%.1f%% confidence)", label, confidence * 100);
        }
        
        public boolean isVulnerable() {
            return "HIGH".equals(label) || "MEDIUM".equals(label);
        }
    }
}
