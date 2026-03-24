package com.cyberthreat.service;

import com.cyberthreat.model.GmailSession;
import com.cyberthreat.model.User;
import com.cyberthreat.repository.GmailSessionRepository;
import com.cyberthreat.repository.UserRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.messaging.simp.SimpMessagingTemplate;
import org.springframework.scheduling.annotation.Async;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Service;

import java.time.LocalDateTime;
import java.util.HashMap;
import java.util.Map;
import java.util.UUID;
import java.util.concurrent.ConcurrentHashMap;

@Service
public class GmailMonitorService {

    @Autowired
    private UserRepository userRepository;

    @Autowired
    private GmailSessionRepository gmailSessionRepository;

    @Autowired
    private SimpMessagingTemplate messagingTemplate;

    @Value("${gmail.monitoring.enabled:true}")
    private boolean monitoringEnabled;

    // Store user's access tokens
    private Map<Long, String> userAccessTokens = new ConcurrentHashMap<>();

    @Async
    public void startMonitoring(Long userId, String accessToken) {
        if (!monitoringEnabled) {
            System.out.println("⚠️ Gmail monitoring is disabled");
            return;
        }

        userAccessTokens.put(userId, accessToken);
        System.out.println("✅ Started Gmail monitoring for user ID: " + userId);
        
        User user = userRepository.findById(userId).orElse(null);
        if (user != null) {
            // Send confirmation to frontend
            Map<String, Object> message = new HashMap<>();
            message.put("type", "MONITORING_STARTED");
            message.put("userId", userId);
            message.put("email", user.getEmail());
            message.put("timestamp", LocalDateTime.now().toString());
            
            messagingTemplate.convertAndSendToUser(
                user.getUsername(),
                "/queue/gmail-alerts",
                message
            );
        }
    }

    public void stopMonitoring(Long userId) {
        userAccessTokens.remove(userId);
        System.out.println("🛑 Stopped Gmail monitoring for user ID: " + userId);
    }

    public void monitorUserGmail(User user) {
        if (user != null && userAccessTokens.containsKey(user.getId())) {
            simulateGmailCheck(user);
        }
    }

    @Scheduled(fixedDelay = 300000) // Run every 5 minutes
    public void checkGmailLogins() {
        if (!monitoringEnabled || userAccessTokens.isEmpty()) {
            return;
        }

        System.out.println("🔍 Checking Gmail logins for " + userAccessTokens.size() + " users...");

        for (Long userId : userAccessTokens.keySet()) {
            User user = userRepository.findById(userId).orElse(null);
            if (user != null) {
                simulateGmailCheck(user);
            }
        }
    }

    private void simulateGmailCheck(User user) {
        // Simulate a new login every 10% chance
        if (Math.random() < 0.1) {
            createGmailAlert(user, 
                "Samsung Galaxy S24", 
                "New Delhi, India", 
                "203.0.113." + (int)(Math.random() * 255));
        }
    }

    public void createGmailAlert(User user, String deviceInfo, String location, String ipAddress) {
        try {
            // Check if this device is already known
            boolean exists = gmailSessionRepository.existsByUserIdAndDeviceId(user.getId(), deviceInfo);
            
            if (!exists) {
                // Create new session
                GmailSession session = new GmailSession();
                session.setUser(user);
                session.setDeviceName(deviceInfo);
                session.setDeviceId("DEV-" + UUID.randomUUID().toString().substring(0, 8));
                session.setIpAddress(ipAddress);
                session.setLocation(location);
                session.setCity(location.split(",")[0].trim());
                session.setCountry(location.split(",")[1].trim());
                session.setVerified(false);
                session.setBlocked(false);
                session.setAlertSent(true);
                
                gmailSessionRepository.save(session);

                // Create alert for frontend
                Map<String, Object> alert = new HashMap<>();
                alert.put("id", session.getId());
                alert.put("userId", user.getId());
                alert.put("email", user.getEmail());
                alert.put("deviceInfo", deviceInfo);
                alert.put("location", location);
                alert.put("ipAddress", ipAddress);
                alert.put("timestamp", LocalDateTime.now().toString());
                alert.put("type", "GMAIL_ACCESS");
                alert.put("suspicious", true);

                // Send WebSocket alert to specific user
                messagingTemplate.convertAndSendToUser(
                    user.getUsername(),
                    "/queue/gmail-alerts",
                    alert
                );

                System.out.println("✅ Gmail login alert sent for user: " + user.getEmail());
            }

        } catch (Exception e) {
            System.err.println("❌ Error creating Gmail alert: " + e.getMessage());
        }
    }

    public void storeAccessToken(String email, String accessToken) {
        User user = userRepository.findByEmail(email).orElse(null);
        if (user != null) {
            startMonitoring(user.getId(), accessToken);
        }
    }
}