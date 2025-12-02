package com.security.ai.agent;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.List;
import java.util.UUID;
import java.util.concurrent.*;
import java.util.concurrent.atomic.AtomicReference;

/**
 * Abstract base implementation of SecurityAgent using Java 25 virtual threads
 * and structured concurrency for efficient agent operation.
 */
public abstract class AbstractSecurityAgent implements SecurityAgent {
    
    protected final Logger logger = LoggerFactory.getLogger(getClass());
    protected final String agentId;
    protected final AtomicReference<AgentStatus> status;
    protected volatile Thread agentThread;
    protected final ExecutorService virtualThreadExecutor;
    
    protected AbstractSecurityAgent() {
        this.agentId = UUID.randomUUID().toString();
        this.status = new AtomicReference<>(AgentStatus.INITIALIZING);
        this.virtualThreadExecutor = Executors.newVirtualThreadPerTaskExecutor();
    }
    
    @Override
    public String getAgentId() {
        return agentId;
    }
    
    @Override
    public AgentStatus getStatus() {
        return status.get();
    }
    
    @Override
    public void start() {
        if (status.compareAndSet(AgentStatus.INITIALIZING, AgentStatus.RUNNING) ||
            status.compareAndSet(AgentStatus.STOPPED, AgentStatus.RUNNING)) {
            
            logger.info("Starting security agent: {} [{}]", getType(), agentId);
            
            agentThread = Thread.ofVirtual().start(() -> {
                try {
                    initialize();
                    runAgentLoop();
                } catch (Exception e) {
                    logger.error("Agent {} encountered error", agentId, e);
                    status.set(AgentStatus.ERROR);
                }
            });
        }
    }
    
    @Override
    public void stop() {
        if (status.compareAndSet(AgentStatus.RUNNING, AgentStatus.STOPPED) ||
            status.compareAndSet(AgentStatus.PAUSED, AgentStatus.STOPPED)) {
            
            logger.info("Stopping security agent: {} [{}]", getType(), agentId);
            
            try {
                cleanup();
                if (agentThread != null && agentThread.isAlive()) {
                    agentThread.interrupt();
                }
                virtualThreadExecutor.shutdown();
                if (!virtualThreadExecutor.awaitTermination(10, TimeUnit.SECONDS)) {
                    virtualThreadExecutor.shutdownNow();
                }
            } catch (Exception e) {
                Thread.currentThread().interrupt();
                logger.warn("Agent shutdown interrupted", e);
            }
        }
    }
    
    @Override
    public CompletableFuture<List<SecurityFinding>> analyze(SecurityEvent event) {
        if (status.get() != AgentStatus.RUNNING) {
            return CompletableFuture.failedFuture(
                new IllegalStateException("Agent is not running")
            );
        }
        
        return CompletableFuture.supplyAsync(() -> {
            try {
                logger.debug("Agent {} analyzing event: {}", agentId, event.eventId());
                return performAnalysis(event);
            } catch (Exception e) {
                logger.error("Analysis failed for event: {}", event.eventId(), e);
                throw new CompletionException(e);
            }
        }, virtualThreadExecutor);
    }
    
    /**
     * Initialize agent-specific resources
     */
    protected abstract void initialize() throws Exception;
    
    /**
     * Main agent execution loop
     */
    protected abstract void runAgentLoop() throws Exception;
    
    /**
     * Perform analysis on security event
     */
    protected abstract List<SecurityFinding> performAnalysis(SecurityEvent event) throws Exception;
    
    /**
     * Cleanup agent resources
     */
    protected abstract void cleanup() throws Exception;
    
    /**
     * Utility method for structured concurrency task execution
     */
    protected <T> List<T> executeParallelTasks(List<Callable<T>> tasks) throws Exception {
        try (var scope = StructuredTaskScope.open()) {
            var subtasks = tasks.stream()
                .map(scope::fork)
                .toList();
            
            scope.join();
            
            return subtasks.stream()
                .map(StructuredTaskScope.Subtask::get)
                .toList();
        }
    }
}
