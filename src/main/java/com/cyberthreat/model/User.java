package com.cyberthreat.model;

import com.fasterxml.jackson.annotation.JsonManagedReference;
import jakarta.persistence.*;
import java.time.LocalDateTime;
import java.util.List;

@Entity
@Table(name = "users")
public class User {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(unique = true, nullable = false)
    private String username;

    @Column(nullable = false)
    private String password;

    @Column(unique = true, nullable = false)
    private String email;

    private String firstName;
    private String lastName;

    @Enumerated(EnumType.STRING)
    @Column(nullable = false)
    private UserRole role = UserRole.ROLE_USER;

    private LocalDateTime createdAt;
    private LocalDateTime lastLogin;

    @Column(name = "enabled")
    private Boolean enabled = true;

    // OAuth2 Fields
    @Column(name = "google_id", unique = true)
    private String googleId;

    @Column(name = "picture_url")
    private String pictureUrl;

    @Column(name = "email_verified")
    private Boolean emailVerified;

    @Column(name = "provider")
    private String provider;

    // Gmail Monitoring Fields
    @Column(name = "gmail_access_token", length = 2000)
    private String gmailAccessToken;

    @Column(name = "gmail_refresh_token", length = 500)
    private String gmailRefreshToken;

    @Column(name = "gmail_token_expiry")
    private LocalDateTime gmailTokenExpiry;

    @Column(name = "gmail_connected")
    private Boolean gmailConnected = false;

    @Column(name = "gmail_email")
    private String gmailEmail;

    // Relationships
    @OneToMany(mappedBy = "user", cascade = CascadeType.ALL, fetch = FetchType.LAZY)
    @JsonManagedReference
    private List<UserSession> sessions;

    @OneToMany(mappedBy = "user", cascade = CascadeType.ALL, fetch = FetchType.LAZY)
    private List<Device> devices;

    @OneToMany(mappedBy = "user", cascade = CascadeType.ALL, fetch = FetchType.LAZY)
    private List<GmailSession> gmailSessions;

    // ===== ENUM =====
    public enum UserRole {
        ROLE_USER,
        ROLE_ADMIN
    }

    // ===== GETTERS & SETTERS =====

    public Long getId() {
        return id;
    }

    public void setId(Long id) {
        this.id = id;
    }

    public String getUsername() {
        return username;
    }

    public void setUsername(String username) {
        this.username = username;
    }

    public String getPassword() {
        return password;
    }

    public void setPassword(String password) {
        this.password = password;
    }

    public String getEmail() {
        return email;
    }

    public void setEmail(String email) {
        this.email = email;
    }

    public String getFirstName() {
        return firstName;
    }

    public void setFirstName(String firstName) {
        this.firstName = firstName;
    }

    public String getLastName() {
        return lastName;
    }

    public void setLastName(String lastName) {
        this.lastName = lastName;
    }

    public UserRole getRole() {
        return role;
    }

    public void setRole(UserRole role) {
        this.role = role;
    }

    public LocalDateTime getCreatedAt() {
        return createdAt;
    }

    public void setCreatedAt(LocalDateTime createdAt) {
        this.createdAt = createdAt;
    }

    public LocalDateTime getLastLogin() {
        return lastLogin;
    }

    public void setLastLogin(LocalDateTime lastLogin) {
        this.lastLogin = lastLogin;
    }

    public Boolean getEnabled() {
        return enabled;
    }
    
    public void setEnabled(Boolean enabled) {
        this.enabled = enabled;
    }
    
    public boolean isEnabled() {
        return enabled != null ? enabled : true;
    }

    public List<Device> getDevices() {
        return devices;
    }

    public void setDevices(List<Device> devices) {
        this.devices = devices;
    }

    // OAuth2 Getters/Setters
    public String getGoogleId() {
        return googleId;
    }

    public void setGoogleId(String googleId) {
        this.googleId = googleId;
    }

    public String getPictureUrl() {
        return pictureUrl;
    }

    public void setPictureUrl(String pictureUrl) {
        this.pictureUrl = pictureUrl;
    }

    public Boolean getEmailVerified() {
        return emailVerified;
    }

    public void setEmailVerified(Boolean emailVerified) {
        this.emailVerified = emailVerified;
    }

    public String getProvider() {
        return provider;
    }

    public void setProvider(String provider) {
        this.provider = provider;
    }

    // Gmail Getters/Setters
    public String getGmailAccessToken() {
        return gmailAccessToken;
    }

    public void setGmailAccessToken(String gmailAccessToken) {
        this.gmailAccessToken = gmailAccessToken;
    }

    public String getGmailRefreshToken() {
        return gmailRefreshToken;
    }

    public void setGmailRefreshToken(String gmailRefreshToken) {
        this.gmailRefreshToken = gmailRefreshToken;
    }

    public LocalDateTime getGmailTokenExpiry() {
        return gmailTokenExpiry;
    }

    public void setGmailTokenExpiry(LocalDateTime gmailTokenExpiry) {
        this.gmailTokenExpiry = gmailTokenExpiry;
    }

    public Boolean getGmailConnected() {
        return gmailConnected;
    }

    public boolean isGmailConnected() {
        return gmailConnected != null ? gmailConnected : false;
    }

    public void setGmailConnected(Boolean gmailConnected) {
        this.gmailConnected = gmailConnected;
    }

    public String getGmailEmail() {
        return gmailEmail;
    }

    public void setGmailEmail(String gmailEmail) {
        this.gmailEmail = gmailEmail;
    }

    public List<GmailSession> getGmailSessions() {
        return gmailSessions;
    }

    public void setGmailSessions(List<GmailSession> gmailSessions) {
        this.gmailSessions = gmailSessions;
    }

    public List<UserSession> getSessions() {
        return sessions;
    }

    public void setSessions(List<UserSession> sessions) {
        this.sessions = sessions;
    }

    // ===== JPA CALLBACK =====
    @PrePersist
    protected void onCreate() {
        this.createdAt = LocalDateTime.now();
        if (this.emailVerified == null) {
            this.emailVerified = false;
        }
        if (this.enabled == null) {
            this.enabled = true;
        }
        if (this.gmailConnected == null) {
            this.gmailConnected = false;
        }
    }

    @PreUpdate
    protected void onUpdate() {
        // Update logic if needed
    }

    // ===== HELPER METHODS =====
    public boolean isGmailTokenExpired() {
        if (this.gmailTokenExpiry == null) return true;
        return LocalDateTime.now().isAfter(this.gmailTokenExpiry);
    }

    @Override
    public String toString() {
        return "User{" +
                "id=" + id +
                ", username='" + username + '\'' +
                ", email='" + email + '\'' +
                ", role=" + role +
                ", gmailConnected=" + gmailConnected +
                '}';
    }
}