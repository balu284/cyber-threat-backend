package com.cyberthreat.model;

import com.fasterxml.jackson.annotation.JsonProperty;
import java.util.List;

public class AgentReport<ThreatData> {

    @JsonProperty("agentId")
    private String agentId;

    @JsonProperty("agentName")
    private String agentName;

    @JsonProperty("threats")
    private List<ThreatData> threats;

    @JsonProperty("systemInfo")
    private SystemInfo systemInfo;   // ✅ uses correct class

    @JsonProperty("timestamp")
    private String timestamp;

    public String getAgentId() { return agentId; }
    public void setAgentId(String agentId) { this.agentId = agentId; }

    public String getAgentName() { return agentName; }
    public void setAgentName(String agentName) { this.agentName = agentName; }

    public List<ThreatData> getThreats() { return threats; }
    public void setThreats(List<ThreatData> threats) { this.threats = threats; }

    public SystemInfo getSystemInfo() { return systemInfo; }
    public void setSystemInfo(SystemInfo systemInfo) { this.systemInfo = systemInfo; }

    public String getTimestamp() { return timestamp; }
    public void setTimestamp(String timestamp) { this.timestamp = timestamp; }
}
