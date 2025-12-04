# 🛡️ JavaShield - AI-Powered Security Vulnerability Detection Platform

<p align="center">
  <img src="https://img.shields.io/badge/Java-25-orange?style=for-the-badge&logo=openjdk" alt="Java 25"/>
  <img src="https://img.shields.io/badge/Spring_Boot-3.4.0-green?style=for-the-badge&logo=springboot" alt="Spring Boot"/>
  <img src="https://img.shields.io/badge/ML-Tribuo_+_DL4J-blue?style=for-the-badge&logo=pytorch" alt="ML"/>
  <img src="https://img.shields.io/badge/OWASP_ZAP-2.16.1-red?style=for-the-badge&logo=owasp" alt="OWASP ZAP"/>
</p>

---

## 📖 What is JavaShield?

**JavaShield** is an intelligent security platform that automatically detects and fixes vulnerabilities in Java code using **Machine Learning (ML)** and **Deep Learning (DL)**. Think of it as a smart security guard for your code that:

1. **Scans** your Java code for security problems
2. **Analyzes** using multiple detection engines (like having multiple experts review your code)
3. **Classifies** vulnerabilities using trained AI models
4. **Fixes** the issues automatically with one click

---

## 🎯 Why This Project?

Every year, thousands of security breaches happen because of vulnerabilities in code. Common problems include:

| Problem | What Can Happen |
|---------|-----------------|
| **SQL Injection** | Attackers can steal your entire database |
| **Path Traversal** | Attackers can read any file on your server (passwords, configs) |
| **Insecure Network** | Data sent without encryption - anyone can read it |
| **Weak Cryptography** | Passwords easily cracked |
| **Command Injection** | Attackers can run commands on your server |

**JavaShield solves this** by combining traditional security tools with AI to find AND fix these problems automatically.

---

## 🏗️ Architecture Overview

Here's how all the components work together:

```
┌─────────────────────────────────────────────────────────────────────────┐
│                        JavaShield Architecture                          │
├─────────────────────────────────────────────────────────────────────────┤
│                                                                         │
│  ┌─────────────┐     ┌─────────────────────────────────────────────┐   │
│  │   Frontend  │────▶│           REST API (Spring Boot)             │   │
│  │   (HTML/JS) │     │           Port 8080                          │   │
│  └─────────────┘     └──────────────────┬──────────────────────────┘   │
│                                          │                              │
│                      ┌───────────────────┼───────────────────┐         │
│                      ▼                   ▼                   ▼         │
│              ┌──────────────┐   ┌──────────────┐   ┌──────────────┐   │
│              │   Static     │   │    ML/DL     │   │   Dynamic    │   │
│              │  Analyzers   │   │   Models     │   │  Analyzers   │   │
│              └──────────────┘   └──────────────┘   └──────────────┘   │
│                     │                   │                   │          │
│         ┌──────────┬┴─────────┐        │         ┌─────────┴────────┐ │
│         ▼          ▼          ▼        │         ▼                  ▼ │
│      ┌─────┐   ┌─────┐   ┌───────┐    │    ┌──────────┐    ┌────────┐│
│      │ PMD │   │Spot │   │Custom │    │    │OWASP ZAP │    │Runtime ││
│      │     │   │Bugs │   │ AST   │    │    │ Scanner  │    │Monitor ││
│      └─────┘   └─────┘   └───────┘    │    └──────────┘    └────────┘│
│                                        │                              │
│                           ┌────────────┴────────────┐                 │
│                           ▼                         ▼                 │
│                    ┌────────────┐           ┌────────────┐            │
│                    │  Tribuo    │           │    DL4J    │            │
│                    │ Ensemble   │           │  Neural    │            │
│                    │ (ML)       │           │  Network   │            │
│                    └────────────┘           └────────────┘            │
│                                                                        │
└────────────────────────────────────────────────────────────────────────┘
```

### What does each component do?

| Component | Type | Job |
|-----------|------|-----|
| **Frontend** | Web UI | Where you paste code and see results |
| **Spring Boot API** | Backend | Receives requests, coordinates everything |
| **PMD** | Static Analysis | Checks code against 17 security rules |
| **SpotBugs** | Static Analysis | Finds bug patterns in compiled code |
| **Custom AST** | Static Analysis | Parses code structure (Abstract Syntax Tree) |
| **OWASP ZAP** | Dynamic Analysis | Tests running applications for vulnerabilities |
| **Runtime Monitor** | Dynamic Analysis | Watches code behavior in real-time |
| **Tribuo ML** | Machine Learning | Classifies code using trained models |
| **DL4J Neural Network** | Deep Learning | Advanced AI classification |

---

## 🧠 How the Machine Learning Works

### Simple Explanation

Imagine teaching a child to recognize dangerous animals:
1. You show them **many pictures** of dangerous animals (training data)
2. They learn **patterns** (sharp teeth, bright colors = danger)
3. Now they can **identify new** dangerous animals they've never seen

That's exactly what our ML does with code! We show it thousands of examples of vulnerable code, it learns the patterns, and then it can identify new vulnerabilities.

### Training Data Sources (1,457 examples total)

| Source | Examples | What It Contains |
|--------|----------|------------------|
| **NVD (National Vulnerability Database)** | 200 | Real CVE vulnerability patterns from NIST |
| **MISP (Threat Intelligence)** | 150 | Threat patterns from security community |
| **OWASP Top 10** | 120 | Most common web vulnerabilities |
| **Custom Patterns** | 987 | Our own labeled code samples |

### Feature Extraction (150 features)

The system looks at 150 different things in your code:

```
📊 Feature Categories (150 total)
├── 🔑 Keyword Presence (50 features)
│   └── Does the code contain "executeQuery", "getParameter", "exec"?
│
├── 🔍 Pattern Detection (40 features)  
│   └── SQL patterns, XSS patterns, injection patterns
│
├── 📐 Code Structure (30 features)
│   └── Line length, nesting depth, method complexity
│
└── 🛡️ Security Indicators (30 features)
    └── Uses encryption? Has input validation? Sanitizes data?
```

### The Models

#### 1️⃣ Tribuo Ensemble (Traditional ML)

Think of this as having **two experts vote** on whether code is vulnerable:

```
┌─────────────────────────────────────────────────┐
│           ENSEMBLE CLASSIFIER                    │
├─────────────────────────────────────────────────┤
│  ┌─────────────────┐  ┌─────────────────────┐  │
│  │    Logistic     │  │      AdaBoost       │  │
│  │   Regression    │  │    (50 rounds)      │  │
│  │                 │  │                     │  │
│  │  Fast & simple  │  │  Combines many weak │  │
│  │  good baseline  │  │  learners → strong  │  │
│  └─────────────────┘  └─────────────────────┘  │
│                                                 │
│  Combined Accuracy: 95.55% ✅                   │
└─────────────────────────────────────────────────┘
```

#### 2️⃣ DL4J Neural Network (Deep Learning)

A **4-layer brain** that processes code:

```
┌──────────────────────────────────────────────────┐
│              NEURAL NETWORK                       │
├──────────────────────────────────────────────────┤
│                                                   │
│  INPUT LAYER          150 neurons (features)      │
│       ↓                                          │
│  HIDDEN LAYER 1       256 neurons + ReLU         │
│       ↓               (learns basic patterns)    │
│  HIDDEN LAYER 2       128 neurons + ReLU         │
│       ↓               (combines patterns)        │
│  HIDDEN LAYER 3       64 neurons + ReLU          │
│       ↓               (high-level features)      │
│  OUTPUT LAYER         4 neurons (categories)     │
│                                                   │
│  Total Parameters: 80,068                        │
│  Optimizer: Adam (learns efficiently)            │
└──────────────────────────────────────────────────┘
```

**What do the layers do?**
- **Layer 1**: Learns simple patterns ("contains SQL keyword")
- **Layer 2**: Combines patterns ("SQL keyword + user input = danger")
- **Layer 3**: Abstract concepts ("this looks like SQL injection")
- **Output**: Final decision (VULNERABLE, SUSPICIOUS, SAFE, UNKNOWN)

### Classification Results

| Category | What It Means | Accuracy |
|----------|---------------|----------|
| 🔴 **VULNERABLE** | Definite security issue, must fix | 98.99% |
| 🟡 **SUSPICIOUS** | Might be a problem, should review | 72.97% |
| 🟢 **SAFE** | No issues detected | 98.21% |
| ⚪ **UNKNOWN** | Not enough info, needs manual check | - |

---

## 🔧 Technologies Explained

### Backend Technologies

| Technology | What It Is | Why We Use It |
|------------|------------|---------------|
| **Java 25** | Programming language | Latest features like Virtual Threads (super fast!) |
| **Spring Boot 3.4** | Web framework | Makes building REST APIs easy |
| **Maven** | Build tool | Manages all our dependencies |

### Machine Learning Stack

| Technology | What It Is | Why We Use It |
|------------|------------|---------------|
| **Tribuo 4.3.1** | Oracle's ML library | Easy to train classification models |
| **DL4J 1.0.0-M2.1** | Deep learning library | Build neural networks in Java |
| **ND4J** | Math library | Fast matrix operations for DL4J |
| **ONNX Runtime** | ML inference | Run pre-trained models |

### Static Analysis Tools (Analyze WITHOUT running code)

| Tool | What It Does | Example Finding |
|------|--------------|-----------------|
| **PMD** | Checks code against rules | "Don't use string concatenation in SQL" |
| **SpotBugs** | Finds bug patterns | "Null pointer possible here" |
| **Custom AST** | Parses code structure | "User input flows to database query" |
| **JQAssistant** | Graph-based analysis | "Class A depends on insecure Class B" |

### Dynamic Analysis Tools (Analyze RUNNING code)

| Tool | What It Does |
|------|--------------|
| **OWASP ZAP** | Attacks running web app to find vulnerabilities |
| **Runtime Monitor** | Watches what the code does when executing |

### Data Sources

| Source | What It Provides |
|--------|------------------|
| **NVD (NIST)** | CVE database - all known vulnerabilities |
| **MISP** | Threat intelligence from security community |

---

## 📁 Project Structure (Simplified)

```
jabaproj/
│
├── 📂 src/main/java/com/security/ai/
│   │
│   ├── 📂 unified/                    ⭐ THE CORE ENGINE
│   │   ├── UnifiedMLSecurityAgent.java    # Main brain - coordinates everything
│   │   ├── DeepLearningSecurityModel.java # Neural network implementation
│   │   ├── PMDAnalyzer.java               # Runs PMD analysis
│   │   ├── SpotBugsAnalyzer.java          # Runs SpotBugs analysis
│   │   ├── CustomASTAnalyzer.java         # Our custom code parser
│   │   ├── OwaspZapNativeScanner.java     # Connects to OWASP ZAP
│   │   ├── NVDClient.java                 # Fetches CVE data
│   │   ├── MISPClient.java                # Fetches threat intel
│   │   └── VulnerabilityTrainingDataset.java # Training data builder
│   │
│   └── 📂 web/controller/
│       └── SecurityAgentController.java   # REST API endpoints
│
├── 📂 src/main/resources/
│   └── static/index.html             # The web interface you see
│
├── 📂 test-samples/                  # Example vulnerable code
│   ├── SQLInjection.java
│   ├── PathTraversal.java
│   └── InsecureNetwork.java
│
├── pom.xml                           # All dependencies listed here
└── README.md                         # You're reading this!
```

---

## 🚀 Quick Start Guide

### What You Need First

1. ✅ **Java 25** - [Download here](https://www.oracle.com/java/technologies/downloads/)
2. ✅ **Maven 3.9+** - [Download here](https://maven.apache.org/download.cgi)
3. ⭐ **OWASP ZAP** (optional but cool) - [Download here](https://www.zaproxy.org/download/)

### Step-by-Step Setup

```bash
# 1. Clone (download) the project
git clone https://github.com/maaahhdiii/javashild.git
cd javashild

# 2. Build (compile all the code)
mvn clean package -DskipTests

# 3. Run (start the server)
java --enable-preview -jar target/vulnerability-detection-agent-1.0.0.jar

# 4. Open in browser
# Go to: http://localhost:8080
```

### What Happens When You Start?

```
Starting JavaShield...
✅ Loading 1,457 training examples...
✅ Training Logistic Regression model...
✅ Training AdaBoost model (50 rounds)...
✅ Accuracy: 95.55% (280/292 correct)
✅ Initializing DL4J Neural Network...
✅ Neural Network: 150→256→128→64→4 (80,068 params)
✅ PMD Analyzer ready (17 rules)
✅ SpotBugs Analyzer ready
✅ Custom AST Analyzer ready
✅ Connecting to OWASP ZAP...
✅ Connected to ZAP version 2.16.1
✅ Server started on port 8080

Ready! Open http://localhost:8080
```

---

## 🖥️ Using the Web Interface

### Step 1: Enter Your Code

Copy/paste Java code or click "Load Sample" to test with vulnerable examples.

### Step 2: Click "Analyze with ML"

The system will:
1. Run all static analyzers (PMD, SpotBugs, AST)
2. Extract 150 features from your code
3. Classify with ML/DL models
4. Show you the results

### Step 3: Understand the Results

Each finding shows:
- **Severity**: CRITICAL 🔴, HIGH 🟠, MEDIUM 🟡, LOW 🟢
- **Confidence**: How sure the detector is (0-100%)
- **ML Verdict**: What the AI thinks (VULNERABLE, SUSPICIOUS, SAFE)
- **Recommendations**: How to fix it

### Step 4: Auto-Fix with One Click

Two buttons:
- **"Fix All Vulnerabilities"** - Uses pattern matching
- **"ML-Powered Fix (AI)"** - Uses ML to generate context-aware fixes

---

## 📡 REST API Endpoints

If you want to use JavaShield programmatically (from other code):

### Analyze Code
```http
POST http://localhost:8080/api/security/analyze

Body (JSON):
{
  "code": "String q = \"SELECT * FROM users WHERE id=\" + userId;",
  "filename": "UserService.java"
}
```

### ML-Powered Fix
```http
POST http://localhost:8080/api/security/ml-fix

Body (JSON):
{
  "code": "... your vulnerable code ...",
  "filename": "MyClass.java"
}
```

### Get Statistics
```http
GET http://localhost:8080/api/security/statistics

Response:
{
  "totalScans": 150,
  "totalFindings": 342,
  "mlMetrics": {
    "modelAccuracy": 0.9555,
    "trainingExamples": 1457
  }
}
```

---

## 🔍 Examples of Vulnerabilities We Detect & Fix

### 1. SQL Injection (CRITICAL) 🔴

**The Problem**: Attacker can inject SQL commands through user input

```java
// ❌ VULNERABLE - NEVER do this!
String userId = request.getParameter("id");  // User types: "1 OR 1=1"
String query = "SELECT * FROM users WHERE id=" + userId;
// Becomes: SELECT * FROM users WHERE id=1 OR 1=1  (returns ALL users!)

// ✅ FIXED by JavaShield - Use PreparedStatement
PreparedStatement stmt = conn.prepareStatement(
    "SELECT * FROM users WHERE id=?"
);
stmt.setString(1, userId);  // Safe - treats input as data, not code
```

### 2. Path Traversal (HIGH) 🟠

**The Problem**: Attacker can read any file on your server

```java
// ❌ VULNERABLE
String filename = request.getParameter("file");  // User types: "../../../etc/passwd"
File file = new File("/uploads/" + filename);
// Accesses: /etc/passwd (your password file!)

// ✅ FIXED by JavaShield
File file = validatePath("/uploads/", filename);  // Validates path is safe
```

### 3. Insecure Network Connection (HIGH) 🟠

**The Problem**: Data sent without encryption - anyone can read it

```java
// ❌ VULNERABLE - No encryption
Socket socket = new Socket(host, port);  // Plain text!

// ✅ FIXED by JavaShield - Use SSL/TLS
SSLSocketFactory factory = (SSLSocketFactory) SSLSocketFactory.getDefault();
SSLSocket socket = (SSLSocket) factory.createSocket(host, port);  // Encrypted!
```

### 4. Weak Hashing (MEDIUM) 🟡

**The Problem**: MD5 and SHA-1 can be cracked

```java
// ❌ VULNERABLE
MessageDigest md = MessageDigest.getInstance("MD5");  // Weak!

// ✅ FIXED by JavaShield
MessageDigest md = MessageDigest.getInstance("SHA-256");  // Strong!
```

### 5. Command Injection (CRITICAL) 🔴

**The Problem**: Attacker can run commands on your server

```java
// ❌ VULNERABLE
String host = request.getParameter("host");  // User types: "google.com; rm -rf /"
Runtime.getRuntime().exec("ping " + host);  // Deletes everything!

// ✅ FIXED by JavaShield
ProcessBuilder pb = new ProcessBuilder("ping", sanitizedHost);
pb.start();  // Safe - arguments are separate
```

---

## 📊 Performance Numbers

| Metric | Value | What It Means |
|--------|-------|---------------|
| **Overall Accuracy** | 95.55% | 19 out of 20 predictions correct |
| **VULNERABLE Detection** | 98.99% | Almost never misses real vulnerabilities |
| **SAFE Detection** | 98.21% | Rarely flags safe code as vulnerable |
| **Training Examples** | 1,457 | Number of examples model learned from |
| **Neural Network Size** | 80,068 params | Complexity of the deep learning model |
| **Startup Time** | ~5 seconds | Time to load and start |
| **Analysis Time** | <1 second | Time to analyze typical code |

---

## 🔄 How Auto-Fix Works (Step by Step)

```
Your Code
    │
    ▼
┌────────────────────┐
│ 1. DETECT          │  Run PMD + SpotBugs + AST
│    Find issues     │  → Found 5 potential vulnerabilities
└────────┬───────────┘
         ▼
┌────────────────────┐
│ 2. CLASSIFY        │  Run through ML model
│    What type?      │  → SQL Injection, Path Traversal, etc.
└────────┬───────────┘
         ▼
┌────────────────────┐
│ 3. MATCH FIX       │  Look up fix template
│    How to fix?     │  → PreparedStatement for SQL injection
└────────┬───────────┘
         ▼
┌────────────────────┐
│ 4. APPLY FIX       │  Regex replacement
│    Transform code  │  → String concat → PreparedStatement
└────────┬───────────┘
         ▼
┌────────────────────┐
│ 5. VALIDATE        │  Re-analyze fixed code
│    Did it work?    │  → Vulnerability count: 0 ✅
└────────────────────┘
         │
         ▼
    Fixed Code! 🎉
```

---

## 🧪 Test It Yourself

The `test-samples/` folder has intentionally vulnerable code:

| File | What's Wrong |
|------|--------------|
| `SQLInjection.java` | 3 different SQL injection patterns |
| `PathTraversal.java` | 6 file path vulnerabilities |
| `InsecureNetwork.java` | 4 unencrypted connections |
| `WeakCrypto.java` | MD5, SHA-1, weak keys |
| `XSSExample.java` | Cross-site scripting |
| `CommandInjection.java` | OS command injection |

Try loading these in the web interface and watch JavaShield find and fix them!

---

## 🛠️ Common Commands

```bash
# Build the project (first time or after changes)
mvn clean package -DskipTests

# Run the server
java --enable-preview -jar target/vulnerability-detection-agent-1.0.0.jar

# Run with Maven directly (for development)
mvn spring-boot:run

# Just compile (check for errors)
mvn compile

# Run tests
mvn test
```

---

## ❓ Troubleshooting

### "Port 8080 already in use"
Another app is using port 8080. Either:
- Stop that app, or
- Change port in `application.properties`: `server.port=8081`

### "Java version wrong"
Make sure you have Java 25:
```bash
java -version
# Should show: openjdk 25...
```

### "OWASP ZAP not connecting"
1. Make sure ZAP is running
2. Enable the API in ZAP settings
3. Check port 8090 is open

---

## 📚 Want to Learn More?

### Machine Learning
- 🎓 [Google ML Crash Course](https://developers.google.com/machine-learning/crash-course) - Free!
- 📖 [Tribuo Documentation](https://tribuo.org/learn/) - The ML library we use

### Security
- 🔐 [OWASP Top 10](https://owasp.org/www-project-top-ten/) - Most common vulnerabilities
- 📋 [CWE Database](https://cwe.mitre.org/) - All weakness types

### Java
- ☕ [Java 25 Features](https://openjdk.org/projects/jdk/25/) - What's new
- 🍃 [Spring Boot Guide](https://spring.io/guides) - Web framework tutorials

---

## 👨‍💻 Author

**Mahdi** - Computer Science Student

---

## 📜 License

MIT License - Use it however you want! Just give credit.

---

<p align="center">
  <b>🛡️ JavaShield - Making Code Secure, One Vulnerability at a Time 🛡️</b>
  <br><br>
  <i>Built with ☕ Java, 🧠 Machine Learning, and ❤️ Love</i>
</p>
