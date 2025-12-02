package com.security.ai.web.dto;

public class CodeAnalysisRequest {
    private String code;
    private String filename;
    
    public CodeAnalysisRequest() {}
    
    public String getCode() { return code; }
    public void setCode(String code) { this.code = code; }
    
    public String getFilename() { return filename; }
    public void setFilename(String filename) { this.filename = filename; }
}
