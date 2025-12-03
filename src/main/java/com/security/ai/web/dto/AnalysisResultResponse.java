package com.security.ai.web.dto;

import java.util.List;

public class AnalysisResultResponse {
    private String status;
    private List<FindingDto> findings;
    private int totalFindings;
    private int criticalCount;
    private int highCount;
    private String code;
    
    public AnalysisResultResponse() {}
    
    public AnalysisResultResponse(String status, List<FindingDto> findings, int totalFindings, 
                                 int criticalCount, int highCount, String code) {
        this.status = status;
        this.findings = findings;
        this.totalFindings = totalFindings;
        this.criticalCount = criticalCount;
        this.highCount = highCount;
        this.code = code;
    }
    
    public String getStatus() { return status; }
    public void setStatus(String status) { this.status = status; }
    
    public List<FindingDto> getFindings() { return findings; }
    public void setFindings(List<FindingDto> findings) { this.findings = findings; }
    
    public int getTotalFindings() { return totalFindings; }
    public void setTotalFindings(int totalFindings) { this.totalFindings = totalFindings; }
    
    public int getCriticalCount() { return criticalCount; }
    public void setCriticalCount(int criticalCount) { this.criticalCount = criticalCount; }
    
    public int getHighCount() { return highCount; }
    public void setHighCount(int highCount) { this.highCount = highCount; }
    
    public String getCode() { return code; }
    public void setCode(String code) { this.code = code; }
}
