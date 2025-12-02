package com.security.ai.agent;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.*;
import java.util.concurrent.*;
import java.util.stream.Collectors;

/**
 * Orchestrates multiple security agents using Java 25 structured concurrency.
 * Coordinates agent lifecycle, event distribution, and result aggregation.
 */
public class AgentOrchestrator {
    
    private static final Logger logger = LoggerFactory.getLogger(AgentOrchestrator.class);
    
    private final Map<String, SecurityAgent> agents = new ConcurrentHashMap<>();
    private final ExecutorService orchestratorExecutor = Executors.newVirtualThreadPerTaskExecutor();
    private volatile boolean running = false;
    
    /**
     * Register a security agent
     */
    public void registerAgent(SecurityAgent agent) {
        agents.put(agent.getAgentId(), agent);
        logger.info("Registered agent: {} [{}]", agent.getType(), agent.getAgentId());
    }
    
    /**
     * Unregister a security agent
     */
    public void unregisterAgent(String agentId) {
        SecurityAgent agent = agents.remove(agentId);
        if (agent != null) {
            agent.stop();
            logger.info("Unregistered agent: {}", agentId);
        }
    }
    
    /**
     * Start all registered agents
     */
    public void startAll() {
        running = true;
        agents.values().forEach(SecurityAgent::start);
        logger.info("Started {} security agents", agents.size());
    }
    
    /**
     * Stop all agents gracefully
     */
    public void stopAll() {
        running = false;
        agents.values().forEach(SecurityAgent::stop);
        orchestratorExecutor.shutdown();
        logger.info("Stopped all security agents");
    }
    
    /**
     * Distribute event to all relevant agents and aggregate results
     */
    public CompletableFuture<AggregatedFindings> analyzeEvent(SecurityAgent.SecurityEvent event) {
        if (!running) {
            return CompletableFuture.failedFuture(
                new IllegalStateException("Orchestrator is not running")
            );
        }
        
        return CompletableFuture.supplyAsync(() -> {
            try (var scope = StructuredTaskScope.open()) {
                
                // Fork analysis tasks for all running agents
                List<StructuredTaskScope.Subtask<List<SecurityAgent.SecurityFinding>>> subtasks = 
                    agents.values().stream()
                        .filter(agent -> agent.getStatus() == SecurityAgent.AgentStatus.RUNNING)
                        .map(agent -> scope.fork(() -> agent.analyze(event).get()))
                        .toList();
                
                scope.join();
                
                // Aggregate all findings
                List<SecurityAgent.SecurityFinding> allFindings = subtasks.stream()
                    .map(StructuredTaskScope.Subtask::get)
                    .flatMap(List::stream)
                    .toList();
                
                return new AggregatedFindings(event, allFindings);
                
            } catch (Exception e) {
                logger.error("Event analysis failed", e);
                throw new CompletionException(e);
            }
        }, orchestratorExecutor);
    }
    
    /**
     * Get statistics for all agents
     */
    public Map<SecurityAgent.AgentType, Long> getAgentStatistics() {
        return agents.values().stream()
            .collect(Collectors.groupingBy(
                SecurityAgent::getType,
                Collectors.counting()
            ));
    }
    
    /**
     * Get all active agents
     */
    public List<SecurityAgent> getActiveAgents() {
        return new ArrayList<>(agents.values());
    }
    
    /**
     * Aggregated findings from multiple agents
     */
    public record AggregatedFindings(
        SecurityAgent.SecurityEvent event,
        List<SecurityAgent.SecurityFinding> findings
    ) {
        
        public List<SecurityAgent.SecurityFinding> getCriticalFindings() {
            return findings.stream()
                .filter(f -> f.severity() == SecurityAgent.SecurityFinding.Severity.CRITICAL)
                .toList();
        }
        
        public List<SecurityAgent.SecurityFinding> getHighSeverityFindings() {
            return findings.stream()
                .filter(f -> f.severity() == SecurityAgent.SecurityFinding.Severity.HIGH)
                .toList();
        }
        
        public double getAverageConfidence() {
            return findings.stream()
                .mapToDouble(SecurityAgent.SecurityFinding::confidenceScore)
                .average()
                .orElse(0.0);
        }
        
        public boolean hasBlockableThreats() {
            return findings.stream()
                .anyMatch(f -> f.severity() == SecurityAgent.SecurityFinding.Severity.CRITICAL 
                    && f.confidenceScore() > 0.8);
        }
    }
}
