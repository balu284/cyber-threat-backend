package com.cyberthreat.model;

import com.fasterxml.jackson.annotation.JsonProperty;

public class AgentStatus {
    
    @JsonProperty("connected")
    private boolean connected;
    
    @JsonProperty("lastSeen")
    private String lastSeen;
    
    @JsonProperty("threatCount")
    private int threatCount;
    
    @JsonProperty("agentId")
    private String agentId;
    
    // Constructors
    public AgentStatus() {}
    
    public AgentStatus(boolean connected, String lastSeen, int threatCount, String agentId) {
        this.connected = connected;
        this.lastSeen = lastSeen;
        this.threatCount = threatCount;
        this.agentId = agentId;
    }
    
    // Getters and Setters
    public boolean isConnected() {
        return connected;
    }
    
    public void setConnected(boolean connected) {
        this.connected = connected;
    }
    
    public String getLastSeen() {
        return lastSeen;
    }
    
    public void setLastSeen(String lastSeen) {
        this.lastSeen = lastSeen;
    }
    
    public int getThreatCount() {
        return threatCount;
    }
    
    public void setThreatCount(int threatCount) {
        this.threatCount = threatCount;
    }
    
    public String getAgentId() {
        return agentId;
    }
    
    public void setAgentId(String agentId) {
        this.agentId = agentId;
    }
}