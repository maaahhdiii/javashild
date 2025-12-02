package com.security.ai.web.dto;

import java.util.List;

public class FindingDto {
    private String id;
    private String category;
    private String description;
    private String severity;
    private String location;
    private double confidence;
    private List<String> recommendations;
    private boolean autoFixAvailable;
    
    public FindingDto() {}
    
    public FindingDto(String id, String category, String description, String severity, 
                     String location, double confidence, List<String> recommendations, boolean autoFixAvailable) {
        this.id = id;
        this.category = category;
        this.description = description;
        this.severity = severity;
        this.location = location;
        this.confidence = confidence;
        this.recommendations = recommendations;
        this.autoFixAvailable = autoFixAvailable;
    }
    
    public String getId() { return id; }
    public void setId(String id) { this.id = id; }
    
    public String getCategory() { return category; }
    public void setCategory(String category) { this.category = category; }
    
    public String getDescription() { return description; }
    public void setDescription(String description) { this.description = description; }
    
    public String getSeverity() { return severity; }
    public void setSeverity(String severity) { this.severity = severity; }
    
    public String getLocation() { return location; }
    public void setLocation(String location) { this.location = location; }
    
    public double getConfidence() { return confidence; }
    public void setConfidence(double confidence) { this.confidence = confidence; }
    
    public List<String> getRecommendations() { return recommendations; }
    public void setRecommendations(List<String> recommendations) { this.recommendations = recommendations; }
    
    public boolean isAutoFixAvailable() { return autoFixAvailable; }
    public void setAutoFixAvailable(boolean autoFixAvailable) { this.autoFixAvailable = autoFixAvailable; }
}
