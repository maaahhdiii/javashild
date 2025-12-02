package com.security.ai.web.dto;

public class AgentStatusDto {
    private String agentId;
    private String type;
    private String status;
    private String health;
    
    public AgentStatusDto() {}
    
    public AgentStatusDto(String agentId, String type, String status, String health) {
        this.agentId = agentId;
        this.type = type;
        this.status = status;
        this.health = health;
    }
    
    public String getAgentId() { return agentId; }
    public void setAgentId(String agentId) { this.agentId = agentId; }
    
    public String getType() { return type; }
    public void setType(String type) { this.type = type; }
    
    public String getStatus() { return status; }
    public void setStatus(String status) { this.status = status; }
    
    public String getHealth() { return health; }
    public void setHealth(String health) { this.health = health; }
}
