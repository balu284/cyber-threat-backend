package com.cyberthreat.model;

import com.fasterxml.jackson.annotation.JsonProperty;

public class SystemInfo {

    @JsonProperty("cpuPercent")
    private Double cpuPercent;

    @JsonProperty("memoryPercent")
    private Double memoryPercent;

    @JsonProperty("timestamp")
    private String timestamp;

    public Double getCpuPercent() {
        return cpuPercent;
    }

    public void setCpuPercent(Double cpuPercent) {
        this.cpuPercent = cpuPercent;
    }

    public Double getMemoryPercent() {
        return memoryPercent;
    }

    public void setMemoryPercent(Double memoryPercent) {
        this.memoryPercent = memoryPercent;
    }

    public String getTimestamp() {
        return timestamp;
    }

    public void setTimestamp(String timestamp) {
        this.timestamp = timestamp;
    }
}
