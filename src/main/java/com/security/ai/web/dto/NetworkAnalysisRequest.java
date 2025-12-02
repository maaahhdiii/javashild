package com.security.ai.web.dto;

public class NetworkAnalysisRequest {
    private String protocol;
    private String host;
    private int port;
    private String path;
    
    public NetworkAnalysisRequest() {}
    
    public String getProtocol() { return protocol; }
    public void setProtocol(String protocol) { this.protocol = protocol; }
    
    public String getHost() { return host; }
    public void setHost(String host) { this.host = host; }
    
    public int getPort() { return port; }
    public void setPort(int port) { this.port = port; }
    
    public String getPath() { return path; }
    public void setPath(String path) { this.path = path; }
}
