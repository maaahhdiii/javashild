package com.security.ai.web.dto;

import java.util.List;

public class SystemStatusResponse {
    private String status;
    private int totalAgents;
    private int activeAgents;
    private List<AgentStatusDto> agents;
    
    public SystemStatusResponse() {}
    
    public SystemStatusResponse(String status, int totalAgents, int activeAgents, List<AgentStatusDto> agents) {
        this.status = status;
        this.totalAgents = totalAgents;
        this.activeAgents = activeAgents;
        this.agents = agents;
    }
    
    public String getStatus() { return status; }
    public void setStatus(String status) { this.status = status; }
    
    public int getTotalAgents() { return totalAgents; }
    public void setTotalAgents(int totalAgents) { this.totalAgents = totalAgents; }
    
    public int getActiveAgents() { return activeAgents; }
    public void setActiveAgents(int activeAgents) { this.activeAgents = activeAgents; }
    
    public List<AgentStatusDto> getAgents() { return agents; }
    public void setAgents(List<AgentStatusDto> agents) { this.agents = agents; }
}
