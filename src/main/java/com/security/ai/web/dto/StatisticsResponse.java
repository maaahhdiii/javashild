package com.security.ai.web.dto;

import java.util.Map;

public class StatisticsResponse {
    private int activeAgents;
    private int totalScans;
    private int totalFindings;
    private Map<String, Integer> findingsBySeverity;
    
    public StatisticsResponse() {}
    
    public StatisticsResponse(int activeAgents, int totalScans, int totalFindings, 
                             Map<String, Integer> findingsBySeverity) {
        this.activeAgents = activeAgents;
        this.totalScans = totalScans;
        this.totalFindings = totalFindings;
        this.findingsBySeverity = findingsBySeverity;
    }
    
    public int getActiveAgents() { return activeAgents; }
    public void setActiveAgents(int activeAgents) { this.activeAgents = activeAgents; }
    
    public int getTotalScans() { return totalScans; }
    public void setTotalScans(int totalScans) { this.totalScans = totalScans; }
    
    public int getTotalFindings() { return totalFindings; }
    public void setTotalFindings(int totalFindings) { this.totalFindings = totalFindings; }
    
    public Map<String, Integer> getFindingsBySeverity() { return findingsBySeverity; }
    public void setFindingsBySeverity(Map<String, Integer> findingsBySeverity) { 
        this.findingsBySeverity = findingsBySeverity; 
    }
}
