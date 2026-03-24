package com.cyberthreat.model;

import jakarta.persistence.*;
import java.time.LocalDateTime;
import com.fasterxml.jackson.annotation.JsonIgnore;

@Entity
@Table(name = "global_threat_indicators")
public class GlobalThreatIndicator {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(nullable = false)
    private String indicator;

    @Enumerated(EnumType.STRING)
    private IndicatorType type;

    @Enumerated(EnumType.STRING)
    private ThreatSeverity severity;

    @Column(length = 1000)
    private String description;

    private String sourceFeed;
    private LocalDateTime firstSeen;
    private LocalDateTime lastSeen;
    private String confidenceLevel;

    @Column(nullable = false)
    private boolean active = true;

    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "feed_id")
    @JsonIgnore
    private ThreatFeed threatFeed;

    public enum IndicatorType {
        IP_ADDRESS, DOMAIN, URL, FILE_HASH, EMAIL,  PROCESS,         // ← ADD THIS
        SUSPICIOUS_PROCESS,  // ← ADD THIS for more clarity
        CPU_WARNING 
    }

    public enum ThreatSeverity {
        LOW, MEDIUM, HIGH, CRITICAL
    }

    // ================== Getters and Setters ==================

    public Long getId() { return id; }
    public void setId(Long id) { this.id = id; }

    public String getIndicator() { return indicator; }
    public void setIndicator(String indicator) { this.indicator = indicator; }

    public IndicatorType getType() { return type; }
    public void setType(IndicatorType type) { this.type = type; }

    public ThreatSeverity getSeverity() { return severity; }
    public void setSeverity(ThreatSeverity severity) { this.severity = severity; }

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

    public boolean isActive() { return active; }
    public void setActive(boolean active) { this.active = active; }

    public ThreatFeed getThreatFeed() { return threatFeed; }
    public void setThreatFeed(ThreatFeed threatFeed) { this.threatFeed = threatFeed; }

    // ================== Lifecycle ==================

    @PrePersist
    protected void onCreate() {
        if (this.firstSeen == null) {
            this.firstSeen = LocalDateTime.now();
        }
    }
	public Double getLatitude() {
		// TODO Auto-generated method stub
		return null;
	}
	public Double getLongitude() {
		// TODO Auto-generated method stub
		return null;
	}
}
