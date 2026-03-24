package com.cyberthreat.dto;

import java.time.LocalDateTime;

public class UserSessionDTO {
    private Long id;
    private String ipAddress;
    private String deviceInfo;
    private String location;
    private String city;
    private String country;
    private Double latitude;
    private Double longitude;
    private String loginTime;
    private String lastActivity;
    private boolean isActive;
    private boolean isSuspicious;
    private boolean isBlocked;
    private String blockReason;
    private String provider;
    private UserInfoDTO user;

    // Nested DTO for user info
    public static class UserInfoDTO {
        private Long id;
        private String username;
        private String email;

        public UserInfoDTO() {}

        public UserInfoDTO(Long id, String username, String email) {
            this.id = id;
            this.username = username;
            this.email = email;
        }

        // Getters and Setters
        public Long getId() { return id; }
        public void setId(Long id) { this.id = id; }
        public String getUsername() { return username; }
        public void setUsername(String username) { this.username = username; }
        public String getEmail() { return email; }
        public void setEmail(String email) { this.email = email; }
    }

    // Constructors
    public UserSessionDTO() {}

    // Getters and Setters
    public Long getId() { return id; }
    public void setId(Long id) { this.id = id; }

    public String getIpAddress() { return ipAddress; }
    public void setIpAddress(String ipAddress) { this.ipAddress = ipAddress; }

    public String getDeviceInfo() { return deviceInfo; }
    public void setDeviceInfo(String deviceInfo) { this.deviceInfo = deviceInfo; }

    public String getLocation() { return location; }
    public void setLocation(String location) { this.location = location; }

    public String getCity() { return city; }
    public void setCity(String city) { this.city = city; }

    public String getCountry() { return country; }
    public void setCountry(String country) { this.country = country; }

    public Double getLatitude() { return latitude; }
    public void setLatitude(Double latitude) { this.latitude = latitude; }

    public Double getLongitude() { return longitude; }
    public void setLongitude(Double longitude) { this.longitude = longitude; }

    public String getLoginTime() { return loginTime; }
    public void setLoginTime(String loginTime) { this.loginTime = loginTime; }

    public String getLastActivity() { return lastActivity; }
    public void setLastActivity(String lastActivity) { this.lastActivity = lastActivity; }

    public boolean isActive() { return isActive; }
    public void setActive(boolean active) { isActive = active; }

    public boolean isSuspicious() { return isSuspicious; }
    public void setSuspicious(boolean suspicious) { isSuspicious = suspicious; }

    public boolean isBlocked() { return isBlocked; }
    public void setBlocked(boolean blocked) { isBlocked = blocked; }

    public String getBlockReason() { return blockReason; }
    public void setBlockReason(String blockReason) { this.blockReason = blockReason; }

    public String getProvider() { return provider; }
    public void setProvider(String provider) { this.provider = provider; }

    public UserInfoDTO getUser() { return user; }
    public void setUser(UserInfoDTO user) { this.user = user; }
}