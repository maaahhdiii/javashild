package com.security.ai.agent;

import java.time.Instant;
import java.util.List;
import java.util.UUID;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.StructuredTaskScope;

/**
 * Base interface for AI security agents using Java 25 features.
 * All security agents must implement this interface for autonomous operation.
 */
public interface SecurityAgent {
    
    /**
     * Unique identifier for this agent instance
     */
    String getAgentId();
    
    /**
     * Agent type classification
     */
    AgentType getType();
    
    /**
     * Start the agent's autonomous operation using virtual threads
     */
    void start();
    
    /**
     * Stop the agent gracefully
     */
    void stop();
    
    /**
     * Get current agent status
     */
    AgentStatus getStatus();
    
    /**
     * Process a security event and return findings
     */
    CompletableFuture<List<SecurityFinding>> analyze(SecurityEvent event);
    
    /**
     * Agent types for classification
     */
    enum AgentType {
        STATIC_ANALYZER,
        DYNAMIC_ANALYZER,
        ML_CLASSIFIER,
        THREAT_DETECTOR,
        RESPONSE_HANDLER,
        INTEGRATION_BRIDGE
    }
    
    /**
     * Agent operational status
     */
    enum AgentStatus {
        INITIALIZING,
        RUNNING,
        PAUSED,
        STOPPED,
        ERROR
    }
    
    /**
     * Security event to be analyzed
     */
    record SecurityEvent(
        String eventId,
        Instant timestamp,
        EventType type,
        String source,
        Object payload
    ) {
        public SecurityEvent {
            if (eventId == null || eventId.isBlank()) {
                eventId = UUID.randomUUID().toString();
            }
            if (timestamp == null) {
                timestamp = Instant.now();
            }
        }
        
        public enum EventType {
            CODE_CHANGE,
            DEPENDENCY_UPDATE,
            RUNTIME_BEHAVIOR,
            API_CALL,
            FILE_ACCESS,
            NETWORK_REQUEST,
            AUTHENTICATION,
            AUTHORIZATION
        }
    }
    
    /**
     * Security finding result from agent analysis
     */
    record SecurityFinding(
        String findingId,
        Instant detectedAt,
        Severity severity,
        String category,
        String description,
        String location,
        String cveId,
        double confidenceScore,
        List<String> recommendations,
        boolean autoRemediationPossible
    ) {
        public SecurityFinding {
            if (findingId == null || findingId.isBlank()) {
                findingId = UUID.randomUUID().toString();
            }
            if (detectedAt == null) {
                detectedAt = Instant.now();
            }
            if (confidenceScore < 0.0 || confidenceScore > 1.0) {
                throw new IllegalArgumentException("Confidence score must be between 0.0 and 1.0");
            }
        }
        
        public enum Severity {
            CRITICAL(1.0),
            HIGH(0.75),
            MEDIUM(0.50),
            LOW(0.25),
            INFO(0.0);
            
            private final double weight;
            
            Severity(double weight) {
                this.weight = weight;
            }
            
            public double getWeight() {
                return weight;
            }
        }
    }
}
