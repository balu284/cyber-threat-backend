package com.cyberthreat.model;

import jakarta.persistence.*;
import java.time.LocalDateTime;
import java.util.List;
import com.fasterxml.jackson.annotation.JsonIgnore;

@Entity
@Table(name = "threat_feeds")
public class ThreatFeed {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(nullable = false)
    private String name;

    private String description;

    @Column(nullable = false)
    private String feedUrl;

    @Enumerated(EnumType.STRING)
    private FeedType type;

    private String apiKey;

    @Column(nullable = false)
    private boolean enabled = true;

    private int updateIntervalMinutes = 60;
    private LocalDateTime lastUpdated;

    @OneToMany(mappedBy = "threatFeed", fetch = FetchType.LAZY)
    @JsonIgnore
    private List<GlobalThreatIndicator> indicators;

    public enum FeedType {
        FREE, PREMIUM, CUSTOM
    }

    // ================== Getters and Setters ==================

    public Long getId() { return id; }
    public void setId(Long id) { this.id = id; }

    public String getName() { return name; }
    public void setName(String name) { this.name = name; }

    public String getDescription() { return description; }
    public void setDescription(String description) { this.description = description; }

    public String getFeedUrl() { return feedUrl; }
    public void setFeedUrl(String feedUrl) { this.feedUrl = feedUrl; }

    public FeedType getType() { return type; }
    public void setType(FeedType type) { this.type = type; }

    public String getApiKey() { return apiKey; }
    public void setApiKey(String apiKey) { this.apiKey = apiKey; }

    public boolean isEnabled() { return enabled; }
    public void setEnabled(boolean enabled) { this.enabled = enabled; }

    public int getUpdateIntervalMinutes() { return updateIntervalMinutes; }
    public void setUpdateIntervalMinutes(int updateIntervalMinutes) {
        this.updateIntervalMinutes = updateIntervalMinutes;
    }

    public LocalDateTime getLastUpdated() { return lastUpdated; }
    public void setLastUpdated(LocalDateTime lastUpdated) {
        this.lastUpdated = lastUpdated;
    }

    public List<GlobalThreatIndicator> getIndicators() {
        return indicators;
    }
}