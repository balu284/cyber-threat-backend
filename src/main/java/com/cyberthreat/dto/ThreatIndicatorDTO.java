package com.cyberthreat.dto;

import com.cyberthreat.model.GlobalThreatIndicator;
import java.time.LocalDateTime;

public class ThreatIndicatorDTO {

    private Long id;
    private String indicator;
    private GlobalThreatIndicator.IndicatorType type;
    private GlobalThreatIndicator.ThreatSeverity severity;
    private String description;
    private String sourceFeed;
    private LocalDateTime firstSeen;
    private LocalDateTime lastSeen;
    private String confidenceLevel;

    // ✅ ADD THESE TWO FIELDS
    private Double latitude;
    private Double longitude;

    public ThreatIndicatorDTO(GlobalThreatIndicator indicator) {
        this.id = indicator.getId();
        this.indicator = indicator.getIndicator();
        this.type = indicator.getType();
        this.severity = indicator.getSeverity();
        this.description = indicator.getDescription();
        this.sourceFeed = indicator.getSourceFeed();
        this.firstSeen = indicator.getFirstSeen();
        this.lastSeen = indicator.getLastSeen();
        this.confidenceLevel = indicator.getConfidenceLevel();

        // ✅ MAP THEM FROM ENTITY
        this.latitude = indicator.getLatitude();
        this.longitude = indicator.getLongitude();
    }

    public Long getId() { return id; }
    public void setId(Long id) { this.id = id; }

    public String getIndicator() { return indicator; }
    public void setIndicator(String indicator) { this.indicator = indicator; }

    public GlobalThreatIndicator.IndicatorType getType() { return type; }
    public void setType(GlobalThreatIndicator.IndicatorType type) { this.type = type; }

    public GlobalThreatIndicator.ThreatSeverity getSeverity() { return severity; }
    public void setSeverity(GlobalThreatIndicator.ThreatSeverity severity) { this.severity = severity; }

    public String getDescription() { return description; }
    public void setDescription(String description) { this.description = description; }

    public String getSourceFeed() { return sourceFeed; }
    public void setSourceFeed(String sourceFeed) { this.sourceFeed = sourceFeed; }

    public LocalDateTime getFirstSeen() { return firstSeen; }
    public void setFirstSeen(LocalDateTime firstSeen) { this.firstSeen = firstSeen; }

    public LocalDateTime getLastSeen() { return lastSeen; }
    public void setLastSeen(LocalDateTime lastSeen) { this.lastSeen = lastSeen; }

    public String getConfidenceLevel() { return confidenceLevel; }
    public void setConfidenceLevel(String confidenceLevel) { this.confidenceLevel = confidenceLevel; }

    // ✅ ADD GETTERS & SETTERS

    public Double getLatitude() { return latitude; }
    public void setLatitude(Double latitude) { this.latitude = latitude; }

    public Double getLongitude() { return longitude; }
    public void setLongitude(Double longitude) { this.longitude = longitude; }
}
