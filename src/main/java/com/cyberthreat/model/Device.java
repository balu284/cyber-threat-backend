package com.cyberthreat.model;

import jakarta.persistence.*;
import java.time.LocalDateTime;
import java.util.List;
import com.fasterxml.jackson.annotation.JsonIgnore;

@Entity
@Table(name = "devices")
public class Device {
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;
    
    @Column(unique = true, nullable = false)
    private String deviceId;
    
    private String deviceName;
    private String operatingSystem;
    private String ipAddress;
    private String macAddress;
    
    @Enumerated(EnumType.STRING)
    private DeviceStatus status = DeviceStatus.ONLINE;
    
    private LocalDateTime registeredAt;
    private LocalDateTime lastSeen;
    
    @ManyToOne
    @JoinColumn(name = "user_id", nullable = false)
    @JsonIgnore
    private User user;
    
    @OneToMany(mappedBy = "device", cascade = CascadeType.ALL)
    @JsonIgnore
    private List<LocalThreatEvent> threatEvents;
    
    public enum DeviceStatus {
        ONLINE, OFFLINE, SUSPENDED, ACTIVE
    }
    
    // Getters and Setters
    public Long getId() { return id; }
    public void setId(Long id) { this.id = id; }
    
    public String getDeviceId() { return deviceId; }
    public void setDeviceId(String deviceId) { this.deviceId = deviceId; }
    
    public String getDeviceName() { return deviceName; }
    public void setDeviceName(String deviceName) { this.deviceName = deviceName; }
    
    public String getOperatingSystem() { return operatingSystem; }
    public void setOperatingSystem(String operatingSystem) { this.operatingSystem = operatingSystem; }
    
    public String getIpAddress() { return ipAddress; }
    public void setIpAddress(String ipAddress) { this.ipAddress = ipAddress; }
    
    public String getMacAddress() { return macAddress; }
    public void setMacAddress(String macAddress) { this.macAddress = macAddress; }
    
    public DeviceStatus getStatus() { return status; }
    public void setStatus(DeviceStatus status) { this.status = status; }
    
    public LocalDateTime getRegisteredAt() { return registeredAt; }
    public void setRegisteredAt(LocalDateTime registeredAt) { this.registeredAt = registeredAt; }
    
    public LocalDateTime getLastSeen() { return lastSeen; }
    public void setLastSeen(LocalDateTime lastSeen) { this.lastSeen = lastSeen; }
    
    public User getUser() { return user; }
    public void setUser(User user) { this.user = user; }
    
    public List<LocalThreatEvent> getThreatEvents() { return threatEvents; }
    public void setThreatEvents(List<LocalThreatEvent> threatEvents) { this.threatEvents = threatEvents; }
    
    @PrePersist
    protected void onCreate() {
        registeredAt = LocalDateTime.now();
        lastSeen = LocalDateTime.now();
    }
}