package com.security.ai.agent;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.util.concurrent.CompletableFuture;
import java.util.concurrent.TimeUnit;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Test suite for AgentOrchestrator
 */
class AgentOrchestratorTest {
    
    private AgentOrchestrator orchestrator;
    private TestSecurityAgent testAgent;
    
    @BeforeEach
    void setUp() {
        orchestrator = new AgentOrchestrator();
        testAgent = new TestSecurityAgent();
    }
    
    @AfterEach
    void tearDown() {
        if (orchestrator != null) {
            orchestrator.stopAll();
        }
    }
    
    @Test
    void testRegisterAgent() {
        orchestrator.registerAgent(testAgent);
        
        var stats = orchestrator.getAgentStatistics();
        assertEquals(1, stats.get(SecurityAgent.AgentType.STATIC_ANALYZER));
    }
    
    @Test
    void testStartAllAgents() {
        orchestrator.registerAgent(testAgent);
        orchestrator.startAll();
        
        // Wait for agent to start
        try {
            Thread.sleep(500);
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
        }
        
        assertEquals(SecurityAgent.AgentStatus.RUNNING, testAgent.getStatus());
    }
    
    @Test
    void testAnalyzeEvent() throws Exception {
        orchestrator.registerAgent(testAgent);
        orchestrator.startAll();
        
        Thread.sleep(500); // Wait for startup
        
        SecurityAgent.SecurityEvent event = new SecurityAgent.SecurityEvent(
            null, null,
            SecurityAgent.SecurityEvent.EventType.CODE_CHANGE,
            "Test",
            "test-payload"
        );
        
        CompletableFuture<AgentOrchestrator.AggregatedFindings> future = 
            orchestrator.analyzeEvent(event);
        
        var result = future.get(5, TimeUnit.SECONDS);
        
        assertNotNull(result);
        assertNotNull(result.findings());
    }
    
    @Test
    void testStopAllAgents() {
        orchestrator.registerAgent(testAgent);
        orchestrator.startAll();
        
        try {
            Thread.sleep(500);
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
        }
        
        orchestrator.stopAll();
        
        assertEquals(SecurityAgent.AgentStatus.STOPPED, testAgent.getStatus());
    }
    
    /**
     * Test implementation of SecurityAgent
     */
    private static class TestSecurityAgent extends com.security.ai.agent.AbstractSecurityAgent {
        
        @Override
        public AgentType getType() {
            return AgentType.STATIC_ANALYZER;
        }
        
        @Override
        protected void initialize() throws Exception {
            status.set(AgentStatus.RUNNING);
        }
        
        @Override
        protected void runAgentLoop() throws Exception {
            while (status.get() == AgentStatus.RUNNING) {
                Thread.sleep(100);
            }
        }
        
        @Override
        protected java.util.List<SecurityFinding> performAnalysis(SecurityEvent event) throws Exception {
            return java.util.List.of(
                new SecurityFinding(
                    null, null,
                    SecurityFinding.Severity.MEDIUM,
                    "Test Finding",
                    "Test description",
                    "test-location",
                    null,
                    0.75,
                    java.util.List.of("Test recommendation"),
                    false
                )
            );
        }
        
        @Override
        protected void cleanup() throws Exception {
            // No cleanup needed
        }
    }
}
