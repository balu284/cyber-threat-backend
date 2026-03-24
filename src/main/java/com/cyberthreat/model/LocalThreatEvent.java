package com.cyberthreat.model;

import jakarta.persistence.*;
import java.time.LocalDateTime;

@Entity
@Table(name = "local_threat_events")
public class LocalThreatEvent {
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;
    
    @ManyToOne
    @JoinColumn(name = "device_id", nullable = false)
    private Device device;
    
    private String threatIndicator;
    
    @Enumerated(EnumType.STRING)
    private GlobalThreatIndicator.IndicatorType indicatorType;
    
    @Enumerated(EnumType.STRING)
    private GlobalThreatIndicator.ThreatSeverity severity;
    
    @Column(length = 1000)
    private String description;
    
    private LocalDateTime detectedAt;
    private String actionTaken;
    private boolean resolved = false;
    
    // Getters and Setters
    public Long getId() { return id; }
    public void setId(Long id) { this.id = id; }
    
    public Device getDevice() { return device; }
    public void setDevice(Device device) { this.device = device; }
    
    public String getThreatIndicator() { return threatIndicator; }
    public void setThreatIndicator(String threatIndicator) { this.threatIndicator = threatIndicator; }
    
    public GlobalThreatIndicator.IndicatorType getIndicatorType() { return indicatorType; }
    public void setIndicatorType(GlobalThreatIndicator.IndicatorType indicatorType) { this.indicatorType = indicatorType; }
    
    public GlobalThreatIndicator.ThreatSeverity getSeverity() { return severity; }
    public void setSeverity(GlobalThreatIndicator.ThreatSeverity severity) { this.severity = severity; }
    
    public String getDescription() { return description; }
    public void setDescription(String description) { this.description = description; }
    
    public LocalDateTime getDetectedAt() { return detectedAt; }
    public void setDetectedAt(LocalDateTime detectedAt) { this.detectedAt = detectedAt; }
    
    public String getActionTaken() { return actionTaken; }
    public void setActionTaken(String actionTaken) { this.actionTaken = actionTaken; }
    
    public boolean isResolved() { return resolved; }
    public void setResolved(boolean resolved) { this.resolved = resolved; }
    
    @PrePersist
    protected void onCreate() {
        detectedAt = LocalDateTime.now();
    }
}