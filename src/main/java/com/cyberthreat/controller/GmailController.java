package com.cyberthreat.controller;

import com.cyberthreat.model.GmailSession;
import com.cyberthreat.model.User;
import com.cyberthreat.repository.GmailSessionRepository;
import com.cyberthreat.repository.UserRepository;
import com.cyberthreat.service.GmailMonitorService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.bind.annotation.*;

import java.time.LocalDateTime;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.UUID;
import java.util.stream.Collectors;

@RestController
@RequestMapping("/api/gmail")
@CrossOrigin(origins = "http://localhost:4200", allowCredentials = "true")
public class GmailController {

    @Autowired
    private GmailMonitorService gmailMonitorService;

    @Autowired
    private GmailSessionRepository gmailSessionRepository;

    @Autowired
    private UserRepository userRepository;

    @Value("${google.client-id}")
    private String clientId;

    @Value("${google.redirect-uri}")
    private String redirectUri;

    @GetMapping("/auth-url")
    public ResponseEntity<?> getGmailAuthUrl(Authentication authentication) {
        try {
            if (authentication == null || !authentication.isAuthenticated()) {
                return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
                    .body(Map.of("error", "User not authenticated"));
            }
            
            String username = authentication.getName();
            User user = userRepository.findByUsername(username)
                .orElseThrow(() -> new RuntimeException("User not found"));

            String authUrl = "https://accounts.google.com/o/oauth2/v2/auth?" +
                "client_id=" + clientId +
                "&redirect_uri=" + redirectUri +
                "&response_type=code" +
                "&scope=https://www.googleapis.com/auth/gmail.readonly" +
                "&access_type=offline" +
                "&state=" + user.getId();

            return ResponseEntity.ok(Map.of("authUrl", authUrl));

        } catch (Exception e) {
            return ResponseEntity.badRequest().body(Map.of("error", e.getMessage()));
        }
    }

    @GetMapping("/callback")
    public ResponseEntity<?> gmailCallback(
            @RequestParam(required = false) String code, 
            @RequestParam(required = false) String state,
            @RequestParam(required = false) String error) {
        
        try {
            // Log the callback for debugging
            System.out.println("========== GMAIL CALLBACK RECEIVED ==========");
            System.out.println("Code: " + code);
            System.out.println("State: " + state);
            System.out.println("Error: " + error);
            
            // Check if there's an error from Google
            if (error != null) {
                return ResponseEntity.badRequest().body(Map.of(
                    "error", "Google authentication failed",
                    "details", error
                ));
            }
            
            // Validate required parameters
            if (code == null || state == null) {
                return ResponseEntity.badRequest().body(Map.of(
                    "error", "Missing required parameters",
                    "message", "Both code and state are required"
                ));
            }
            
            Long userId = Long.parseLong(state);
            User user = userRepository.findById(userId)
                .orElseThrow(() -> new RuntimeException("User not found with id: " + userId));
            
            // In a real implementation, you would exchange the code for tokens here
            // For now, we'll simulate success
            String accessToken = "sample_access_token_" + UUID.randomUUID().toString();
            
            // Start monitoring (you'll implement this)
            gmailMonitorService.startMonitoring(user.getId(), accessToken);
            
            // Update user status
            user.setGmailConnected(true);
            user.setGmailEmail(user.getEmail());
            userRepository.save(user);
            
            System.out.println("✅ Gmail connected successfully for user: " + user.getUsername());
            
            // Return success response
            Map<String, Object> response = new HashMap<>();
            response.put("message", "Gmail connected successfully");
            response.put("email", user.getEmail());
            response.put("connected", true);
            
            return ResponseEntity.ok(response);

        } catch (NumberFormatException e) {
            System.err.println("❌ Invalid state parameter: " + state);
            return ResponseEntity.badRequest().body(Map.of(
                "error", "Invalid state parameter",
                "message", e.getMessage()
            ));
            
        } catch (Exception e) {
            System.err.println("❌ Error in Gmail callback: " + e.getMessage());
            e.printStackTrace();
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body(Map.of(
                "error", "Failed to connect Gmail",
                "message", e.getMessage()
            ));
        }
    }

    @GetMapping("/status")
    public ResponseEntity<?> getGmailStatus() {
        try {
            // Get authentication from SecurityContextHolder
            Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
            
            if (authentication == null || !authentication.isAuthenticated() || "anonymousUser".equals(authentication.getPrincipal())) {
                return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
                    .body(Map.of(
                        "connected", false,
                        "email", "",
                        "accessCount", 0,
                        "suspiciousAttempts", 0,
                        "lastAccess", null,
                        "error", "User not authenticated"
                    ));
            }
            
            String username = authentication.getName();
            Optional<User> userOpt = userRepository.findByUsername(username);
            
            if (userOpt.isEmpty()) {
                return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
                    .body(Map.of(
                        "connected", false,
                        "email", "",
                        "accessCount", 0,
                        "suspiciousAttempts", 0,
                        "lastAccess", null,
                        "error", "User not found"
                    ));
            }
            
            User user = userOpt.get();

            List<GmailSession> sessions = gmailSessionRepository.findByUserIdOrderByLastSeenDesc(user.getId());
            long suspiciousCount = sessions.stream().filter(s -> !s.isVerified()).count();

            Map<String, Object> status = new HashMap<>();
            status.put("connected", user.getGmailConnected() != null ? user.getGmailConnected() : false);
            status.put("email", user.getGmailEmail() != null ? user.getGmailEmail() : "");
            status.put("accessCount", sessions.size());
            status.put("suspiciousAttempts", suspiciousCount);
            status.put("lastAccess", sessions.isEmpty() ? null : sessions.get(0).getLastSeen());

            return ResponseEntity.ok(status);

        } catch (Exception e) {
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                .body(Map.of(
                    "connected", false,
                    "email", "",
                    "accessCount", 0,
                    "suspiciousAttempts", 0,
                    "lastAccess", null,
                    "error", e.getMessage()
                ));
        }
    }

    @GetMapping("/sessions/unverified")
    public ResponseEntity<?> getUnverifiedSessions() {
        try {
            Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
            
            if (authentication == null || !authentication.isAuthenticated() || "anonymousUser".equals(authentication.getPrincipal())) {
                return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
                    .body(List.of()); // Return empty list on auth failure
            }
            
            String username = authentication.getName();
            Optional<User> userOpt = userRepository.findByUsername(username);
            
            if (userOpt.isEmpty()) {
                return ResponseEntity.ok(List.of()); // Return empty list if user not found
            }
            
            User user = userOpt.get();

            List<GmailSession> unverifiedSessions = gmailSessionRepository.findUnverifiedSessions(user.getId());

            List<Map<String, Object>> alerts = unverifiedSessions.stream().map(session -> {
                Map<String, Object> alert = new HashMap<>();
                alert.put("id", session.getId());
                alert.put("location", session.getLocation() != null ? session.getLocation() : "Unknown location");
                alert.put("ipAddress", session.getIpAddress() != null ? session.getIpAddress() : "Unknown IP");
                alert.put("deviceInfo", session.getDeviceName() != null ? session.getDeviceName() : "Unknown device");
                alert.put("action", "GMAIL_ACCESS");
                alert.put("timestamp", session.getLastSeen() != null ? session.getLastSeen().toString() : LocalDateTime.now().toString());
                alert.put("suspicious", true);
                return alert;
            }).collect(Collectors.toList());

            return ResponseEntity.ok(alerts);

        } catch (Exception e) {
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                .body(List.of());
        }
    }

    @PostMapping("/sessions/{sessionId}/verify")
    public ResponseEntity<?> verifySession(@PathVariable Long sessionId) {
        try {
            Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
            
            if (authentication == null || !authentication.isAuthenticated()) {
                return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
                    .body(Map.of("error", "User not authenticated"));
            }
            
            String username = authentication.getName();
            User user = userRepository.findByUsername(username)
                .orElseThrow(() -> new RuntimeException("User not found"));
            
            GmailSession session = gmailSessionRepository.findById(sessionId)
                .orElseThrow(() -> new RuntimeException("Session not found"));
            
            if (!session.getUser().getId().equals(user.getId())) {
                return ResponseEntity.status(HttpStatus.FORBIDDEN)
                    .body(Map.of("error", "Not authorized"));
            }
            
            session.setVerified(true);
            gmailSessionRepository.save(session);
            
            return ResponseEntity.ok(Map.of("message", "Session verified successfully"));
            
        } catch (Exception e) {
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                .body(Map.of("error", e.getMessage()));
        }
    }

    @PostMapping("/sessions/{sessionId}/block")
    public ResponseEntity<?> blockSession(@PathVariable Long sessionId, @RequestBody(required = false) Map<String, String> request) {
        try {
            Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
            
            if (authentication == null || !authentication.isAuthenticated()) {
                return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
                    .body(Map.of("error", "User not authenticated"));
            }
            
            String username = authentication.getName();
            User user = userRepository.findByUsername(username)
                .orElseThrow(() -> new RuntimeException("User not found"));
            
            GmailSession session = gmailSessionRepository.findById(sessionId)
                .orElseThrow(() -> new RuntimeException("Session not found"));
            
            if (!session.getUser().getId().equals(user.getId())) {
                return ResponseEntity.status(HttpStatus.FORBIDDEN)
                    .body(Map.of("error", "Not authorized"));
            }
            
            session.setBlocked(true);
            session.setBlockReason(request != null ? request.get("reason") : "User blocked");
            gmailSessionRepository.save(session);
            
            return ResponseEntity.ok(Map.of("message", "Session blocked successfully"));
            
        } catch (Exception e) {
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                .body(Map.of("error", e.getMessage()));
        }
    }

    @PostMapping("/disconnect")
    public ResponseEntity<?> disconnectGmail() {
        try {
            Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
            
            if (authentication == null || !authentication.isAuthenticated()) {
                return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
                    .body(Map.of("error", "User not authenticated"));
            }
            
            String username = authentication.getName();
            User user = userRepository.findByUsername(username)
                .orElseThrow(() -> new RuntimeException("User not found"));

            user.setGmailConnected(false);
            user.setGmailAccessToken(null);
            user.setGmailRefreshToken(null);
            userRepository.save(user);
            
            gmailMonitorService.stopMonitoring(user.getId());

            return ResponseEntity.ok(Map.of("message", "Gmail disconnected successfully"));

        } catch (Exception e) {
            return ResponseEntity.badRequest().body(Map.of("error", e.getMessage()));
        }
    }
}