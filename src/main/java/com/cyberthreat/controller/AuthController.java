package com.cyberthreat.controller;

import com.cyberthreat.dto.LoginRequest;
import com.cyberthreat.dto.LoginResponse;
import com.cyberthreat.dto.RegisterRequest;
import com.cyberthreat.dto.UserSessionDTO;
import com.cyberthreat.model.User;
import com.cyberthreat.model.UserSession;
import com.cyberthreat.repository.UserRepository;
import com.cyberthreat.repository.UserSessionRepository;
import com.cyberthreat.service.GmailMonitorService;
import com.cyberthreat.service.JwtService;
import com.cyberthreat.service.UserService;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.validation.Valid;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.mail.SimpleMailMessage;
import org.springframework.mail.javamail.JavaMailSender;
import org.springframework.messaging.simp.SimpMessagingTemplate;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.client.RestTemplate;
import org.springframework.web.context.request.RequestContextHolder;
import org.springframework.web.context.request.ServletRequestAttributes;

import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import java.util.*;

@RestController
@RequestMapping("/api/auth")
@CrossOrigin(origins = "http://localhost:4200", allowedHeaders = "*")
public class AuthController {

    @Autowired
    private AuthenticationManager authenticationManager;

    @Autowired
    private UserService userService;

    @Autowired
    private JwtService jwtService;

    @Autowired
    private UserSessionRepository userSessionRepository;

    @Autowired
    private UserRepository userRepository;

    @Autowired
    private JavaMailSender mailSender;

    @Autowired
    private SimpMessagingTemplate messagingTemplate;

    @Autowired
    private GmailMonitorService gmailMonitorService;

    // Simple in-memory refresh token store
    private Map<String, String> refreshTokenStore = new HashMap<>();

    // ===================== LOGIN WITH SESSION TRACKING =====================
    @PostMapping("/login")
    public ResponseEntity<?> authenticateUser(@Valid @RequestBody LoginRequest loginRequest,
                                              HttpServletRequest request) {
        try {
            System.out.println("========== LOGIN ATTEMPT ==========");
            System.out.println("Username: " + loginRequest.getUsername());
            
            Authentication authentication = authenticationManager.authenticate(
                new UsernamePasswordAuthenticationToken(
                    loginRequest.getUsername(),
                    loginRequest.getPassword()
                )
            );

            System.out.println("✅ Authentication successful");
            
            SecurityContextHolder.getContext().setAuthentication(authentication);

            User user = userService.findByUsername(loginRequest.getUsername());
            if (user == null) {
                System.out.println("❌ User not found in database: " + loginRequest.getUsername());
                return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
                    .body(Map.of("message", "User not found"));
            }

            System.out.println("✅ User found: " + user.getUsername() + ", Role: " + user.getRole());

            String ipAddress = getClientIp(request);
            String userAgent = request.getHeader("User-Agent");
            String deviceInfo = getDeviceInfo(userAgent);
            String browserInfo = getBrowserInfo(userAgent);
            String osInfo = getOperatingSystem(userAgent);
            String fullDeviceInfo = deviceInfo + " | " + osInfo + " | " + browserInfo;
            
            Map<String, String> locationData = getLocationFromIp(ipAddress);
            String location = locationData.get("city") + ", " + locationData.get("country");
            
            UserSession session = new UserSession();
            session.setUser(user);
            session.setIpAddress(ipAddress);
            session.setDeviceInfo(fullDeviceInfo);
            session.setLocation(location);
            session.setCity(locationData.get("city"));
            session.setCountry(locationData.get("country"));
            session.setLatitude(Double.parseDouble(locationData.get("lat")));
            session.setLongitude(Double.parseDouble(locationData.get("lon")));
            session.setProvider("LOCAL");
            
            String jwt = jwtService.generateToken(user.getUsername());
            session.setSessionToken(jwt);
            
            boolean isKnownDevice = checkIfKnownDevice(user.getId(), fullDeviceInfo, ipAddress);
            
            if (!isKnownDevice) {
                session.setSuspicious(true);
                
                Map<String, Object> alert = new HashMap<>();
                alert.put("type", "NEW_LOGIN");
                alert.put("device", fullDeviceInfo);
                alert.put("location", location);
                alert.put("ip", ipAddress);
                alert.put("time", LocalDateTime.now().toString());
                alert.put("suspicious", true);
                alert.put("city", locationData.get("city"));
                alert.put("country", locationData.get("country"));
                
                messagingTemplate.convertAndSendToUser(
                    user.getUsername(),
                    "/queue/alerts",
                    alert
                );
                
                sendLoginAlertEmail(user, fullDeviceInfo, location, ipAddress, locationData);
            }
            
            userSessionRepository.save(session);

            user.setLastLogin(LocalDateTime.now());
            userService.saveUser(user);

            String refreshToken = UUID.randomUUID().toString();
            refreshTokenStore.put(refreshToken, user.getUsername());

            LoginResponse response = new LoginResponse(jwt, user);
            response.setRefreshToken(refreshToken);
            response.setSessionId(session.getId());
            response.setSuspicious(!isKnownDevice);

            System.out.println("✅ Login successful for user: " + loginRequest.getUsername());
            System.out.println("📍 Location: " + location);
            System.out.println("💻 Device: " + fullDeviceInfo);
            System.out.println("🆕 Known device: " + isKnownDevice);
            System.out.println("========== LOGIN SUCCESS ==========");
            
            return ResponseEntity.ok()
                .header("Content-Type", "application/json")
                .body(response);

        } catch (BadCredentialsException e) {
            System.out.println("❌ Bad credentials for user: " + loginRequest.getUsername());
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
                .body(Map.of("message", "Invalid username or password"));
            
        } catch (Exception e) {
            System.out.println("❌ Login error: " + e.getMessage());
            e.printStackTrace();
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                .body(Map.of(
                    "message", "Login failed: " + e.getMessage(),
                    "error", e.getClass().getSimpleName()
                ));
        }
    }

    // ===================== GOOGLE OAUTH2 SUCCESS CALLBACK =====================
    @GetMapping("/oauth2/success")
    public ResponseEntity<?> oauth2Success(@RequestParam(required = false) String token,
                                           HttpServletRequest request) {
        try {
            Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
            String email = authentication.getName();
            
            System.out.println("========== GOOGLE OAUTH2 SUCCESS ==========");
            System.out.println("Email from Google: " + email);
            
            Optional<User> userOpt = userRepository.findByEmail(email);
            User user;
            
            if (userOpt.isEmpty()) {
                return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
                    .body(Map.of("error", "User not found"));
            }
            
            user = userOpt.get();
            
            String jwt = token;
            if (jwt == null || jwt.isEmpty()) {
                jwt = jwtService.generateToken(user.getUsername());
            }
            
            String ipAddress = getClientIp(request);
            String userAgent = request.getHeader("User-Agent");
            String deviceInfo = getDeviceInfo(userAgent);
            String browserInfo = getBrowserInfo(userAgent);
            String osInfo = getOperatingSystem(userAgent);
            String fullDeviceInfo = deviceInfo + " | " + osInfo + " | " + browserInfo;
            
            Map<String, String> locationData = getLocationFromIp(ipAddress);
            String location = locationData.get("city") + ", " + locationData.get("country");
            
            UserSession session = new UserSession();
            session.setUser(user);
            session.setIpAddress(ipAddress);
            session.setDeviceInfo(fullDeviceInfo);
            session.setLocation(location);
            session.setCity(locationData.get("city"));
            session.setCountry(locationData.get("country"));
            session.setLatitude(Double.parseDouble(locationData.get("lat")));
            session.setLongitude(Double.parseDouble(locationData.get("lon")));
            session.setSessionToken(jwt);
            session.setProvider("GOOGLE");
            
            boolean isKnownDevice = checkIfKnownDevice(user.getId(), fullDeviceInfo, ipAddress);
            session.setSuspicious(!isKnownDevice);
            
            userSessionRepository.save(session);
            
            String mockAccessToken = "mock_token_" + UUID.randomUUID().toString();
            gmailMonitorService.startMonitoring(user.getId(), mockAccessToken);
            
            String refreshToken = UUID.randomUUID().toString();
            refreshTokenStore.put(refreshToken, user.getUsername());
            
            user.setLastLogin(LocalDateTime.now());
            userService.saveUser(user);
            
            LoginResponse response = new LoginResponse(jwt, user);
            response.setRefreshToken(refreshToken);
            response.setSessionId(session.getId());
            response.setSuspicious(!isKnownDevice);
            
            System.out.println("✅ Google OAuth2 login successful for: " + user.getUsername());
            System.out.println("📍 Location: " + location);
            System.out.println("💻 Device: " + fullDeviceInfo);
            System.out.println("🆕 Known device: " + isKnownDevice);
            System.out.println("📧 Gmail monitoring started for: " + user.getEmail());
            System.out.println("========== GOOGLE SUCCESS ==========");
            
            return ResponseEntity.ok()
                .header("Content-Type", "application/json")
                .body(response);
            
        } catch (Exception e) {
            e.printStackTrace();
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                .body(Map.of("error", e.getMessage()));
        }
    }

    // ===================== GET GOOGLE LOGIN URL =====================
    @GetMapping("/google/url")
    public ResponseEntity<?> getGoogleLoginUrl() {
        String url = "http://localhost:8080/oauth2/authorization/google";
        return ResponseEntity.ok(Map.of("url", url));
    }

    // ===================== GET USER SESSIONS - FIXED VERSION =====================
    @GetMapping("/sessions")
    public ResponseEntity<?> getUserSessions() {
        try {
            Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
            if (authentication == null || !authentication.isAuthenticated() || 
                "anonymousUser".equals(authentication.getPrincipal())) {
                Map<String, Object> errorResponse = new LinkedHashMap<>();
                errorResponse.put("error", "User not authenticated");
                errorResponse.put("sessions", Collections.emptyList());
                errorResponse.put("activeSessions", Collections.emptyList());
                errorResponse.put("currentSession", null);
                return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
                    .header("Content-Type", "application/json")
                    .body(errorResponse);
            }

            String username = authentication.getName();
            User user = userService.findByUsername(username);
            
            if (user == null) {
                Map<String, Object> errorResponse = new LinkedHashMap<>();
                errorResponse.put("error", "User not found");
                errorResponse.put("sessions", Collections.emptyList());
                errorResponse.put("activeSessions", Collections.emptyList());
                errorResponse.put("currentSession", null);
                return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
                    .header("Content-Type", "application/json")
                    .body(errorResponse);
            }
            
            List<UserSession> allSessions = userSessionRepository.findByUserIdOrderByLoginTimeDesc(user.getId());
            
            List<UserSessionDTO> sessionDTOs = new ArrayList<>();
            List<UserSessionDTO> activeSessionDTOs = new ArrayList<>();
            LocalDateTime thirtyDaysAgo = LocalDateTime.now().minusDays(30);
            
            HttpServletRequest request = ((ServletRequestAttributes) RequestContextHolder.currentRequestAttributes()).getRequest();
            String authHeader = request.getHeader("Authorization");
            String currentSessionToken = null;
            UserSessionDTO currentSessionDTO = null;
            
            if (authHeader != null && authHeader.startsWith("Bearer ")) {
                currentSessionToken = authHeader.substring(7);
            }
            
            for (UserSession session : allSessions) {
                UserSessionDTO dto = new UserSessionDTO();
                dto.setId(session.getId());
                dto.setIpAddress(session.getIpAddress() != null ? session.getIpAddress() : "");
                dto.setDeviceInfo(session.getDeviceInfo() != null ? session.getDeviceInfo() : "");
                dto.setLocation(session.getLocation() != null ? session.getLocation() : "");
                dto.setCity(session.getCity() != null ? session.getCity() : "");
                dto.setCountry(session.getCountry() != null ? session.getCountry() : "");
                dto.setLatitude(session.getLatitude());
                dto.setLongitude(session.getLongitude());
                dto.setLoginTime(session.getLoginTime() != null ? session.getLoginTime().toString() : null);
                dto.setLastActivity(session.getLastActivity() != null ? session.getLastActivity().toString() : null);
                dto.setActive(session.isActive());
                dto.setSuspicious(session.isSuspicious());
                dto.setBlocked(session.isBlocked());
                dto.setBlockReason(session.getBlockReason() != null ? session.getBlockReason() : "");
                dto.setProvider(session.getProvider() != null ? session.getProvider() : "");
                
                UserSessionDTO.UserInfoDTO userInfo = new UserSessionDTO.UserInfoDTO(
                    user.getId(),
                    user.getUsername(),
                    user.getEmail()
                );
                dto.setUser(userInfo);
                
                sessionDTOs.add(dto);
                
                if (session.isActive() && !session.isBlocked() && 
                    session.getLoginTime() != null && session.getLoginTime().isAfter(thirtyDaysAgo)) {
                    activeSessionDTOs.add(dto);
                }
                
                if (currentSessionToken != null && 
                    session.getSessionToken() != null && 
                    session.getSessionToken().equals(currentSessionToken)) {
                    currentSessionDTO = dto;
                }
            }
            
            Map<String, Object> response = new LinkedHashMap<>();
            response.put("sessions", sessionDTOs);
            response.put("activeSessions", activeSessionDTOs);
            response.put("currentSession", currentSessionDTO);
            
            return ResponseEntity.ok()
                .header("Content-Type", "application/json")
                .header("Cache-Control", "no-cache, no-store, must-revalidate")
                .header("Pragma", "no-cache")
                .header("Expires", "0")
                .body(response);
            
        } catch (Exception e) {
            e.printStackTrace();
            Map<String, Object> errorResponse = new LinkedHashMap<>();
            errorResponse.put("error", "Failed to load sessions: " + e.getMessage());
            errorResponse.put("sessions", Collections.emptyList());
            errorResponse.put("activeSessions", Collections.emptyList());
            errorResponse.put("currentSession", null);
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                .header("Content-Type", "application/json")
                .body(errorResponse);
        }
    }

    // ===================== TERMINATE SESSION =====================
    @PostMapping("/sessions/{sessionId}/terminate")
    public ResponseEntity<?> terminateSession(@PathVariable Long sessionId) {
        try {
            Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
            String username = authentication.getName();
            User user = userService.findByUsername(username);
            
            Optional<UserSession> sessionOpt = userSessionRepository.findById(sessionId);
            if (sessionOpt.isEmpty()) {
                return ResponseEntity.notFound().build();
            }
            
            UserSession session = sessionOpt.get();
            
            if (!session.getUser().getId().equals(user.getId())) {
                return ResponseEntity.status(HttpStatus.FORBIDDEN)
                    .body(Map.of("error", "Not authorized to terminate this session"));
            }
            
            session.setActive(false);
            userSessionRepository.save(session);
            
            return ResponseEntity.ok(Map.of(
                "message", "Session terminated successfully",
                "sessionId", sessionId
            ));
            
        } catch (Exception e) {
            e.printStackTrace();
            return ResponseEntity.badRequest().body(Map.of("error", e.getMessage()));
        }
    }

    // ===================== BLOCK DEVICE =====================
    @PostMapping("/sessions/{sessionId}/block")
    public ResponseEntity<?> blockDevice(@PathVariable Long sessionId) {
        try {
            Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
            String username = authentication.getName();
            User user = userService.findByUsername(username);
            
            Optional<UserSession> sessionOpt = userSessionRepository.findById(sessionId);
            if (sessionOpt.isEmpty()) {
                return ResponseEntity.notFound().build();
            }
            
            UserSession session = sessionOpt.get();
            
            if (!session.getUser().getId().equals(user.getId())) {
                return ResponseEntity.status(HttpStatus.FORBIDDEN)
                    .body(Map.of("error", "Not authorized"));
            }
            
            session.setBlocked(true);
            session.setActive(false);
            userSessionRepository.save(session);
            
            return ResponseEntity.ok(Map.of(
                "message", "Device blocked successfully",
                "deviceInfo", session.getDeviceInfo(),
                "ipAddress", session.getIpAddress()
            ));
            
        } catch (Exception e) {
            e.printStackTrace();
            return ResponseEntity.badRequest().body(Map.of("error", e.getMessage()));
        }
    }

    // ===================== TERMINATE ALL OTHER SESSIONS =====================
    @PostMapping("/sessions/terminate-all")
    public ResponseEntity<?> terminateAllOtherSessions() {
        try {
            Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
            String username = authentication.getName();
            User user = userService.findByUsername(username);
            
            HttpServletRequest request = ((ServletRequestAttributes) RequestContextHolder.currentRequestAttributes()).getRequest();
            String authHeader = request.getHeader("Authorization");
            
            if (authHeader == null || !authHeader.startsWith("Bearer ")) {
                return ResponseEntity.badRequest().body(Map.of("error", "Invalid authorization header"));
            }
            
            String token = authHeader.substring(7);
            
            Optional<UserSession> currentSession = userSessionRepository.findBySessionToken(token);
            
            if (currentSession.isPresent()) {
                int terminated = userSessionRepository.terminateOtherSessions(user.getId(), currentSession.get().getId());
                return ResponseEntity.ok(Map.of(
                    "message", "All other sessions terminated",
                    "terminatedCount", terminated
                ));
            } else {
                return ResponseEntity.badRequest().body(Map.of("error", "Current session not found"));
            }
            
        } catch (Exception e) {
            e.printStackTrace();
            return ResponseEntity.badRequest().body(Map.of("error", e.getMessage()));
        }
    }

    // ===================== REFRESH TOKEN =====================
    @PostMapping("/refresh")
    public ResponseEntity<?> refreshToken(@RequestBody Map<String, String> request) {
        try {
            String refreshToken = request.get("refreshToken");
            
            if (refreshToken == null || refreshToken.isEmpty()) {
                return ResponseEntity.badRequest()
                    .body(Map.of("error", "Refresh token is required"));
            }

            String username = refreshTokenStore.get(refreshToken);
            
            if (username == null) {
                return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
                    .body(Map.of("error", "Invalid refresh token"));
            }

            String newToken = jwtService.generateToken(username);
            
            String newRefreshToken = UUID.randomUUID().toString();
            refreshTokenStore.remove(refreshToken);
            refreshTokenStore.put(newRefreshToken, username);

            return ResponseEntity.ok(Map.of(
                "token", newToken,
                "refreshToken", newRefreshToken
            ));

        } catch (Exception e) {
            e.printStackTrace();
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
                .body(Map.of("error", "Failed to refresh token: " + e.getMessage()));
        }
    }

    // ===================== REGISTER =====================
    @PostMapping("/register")
    public ResponseEntity<?> registerUser(@Valid @RequestBody RegisterRequest request) {
        try {
            System.out.println("========== REGISTER ATTEMPT ==========");
            System.out.println("Username: " + request.getUsername());
            System.out.println("Email: " + request.getEmail());
            
            if (userService.findByUsername(request.getUsername()) != null) {
                System.out.println("❌ Username already taken: " + request.getUsername());
                return ResponseEntity.badRequest()
                    .body(Map.of("message", "Username is already taken"));
            }

            if (userService.existsByEmail(request.getEmail())) {
                System.out.println("❌ Email already in use: " + request.getEmail());
                return ResponseEntity.badRequest()
                    .body(Map.of("message", "Email is already in use"));
            }

            User user = new User();
            user.setUsername(request.getUsername());
            user.setEmail(request.getEmail());
            user.setFirstName(request.getFirstName());
            user.setLastName(request.getLastName());
            user.setPassword(userService.encodePassword(request.getPassword()));
            user.setRole(User.UserRole.ROLE_USER);
            user.setEnabled(true);
            user.setCreatedAt(LocalDateTime.now());
            user.setProvider("LOCAL");

            User savedUser = userService.saveUser(user);
            System.out.println("✅ User saved with ID: " + savedUser.getId());

            String jwt = jwtService.generateToken(savedUser.getUsername());
            
            String refreshToken = UUID.randomUUID().toString();
            refreshTokenStore.put(refreshToken, savedUser.getUsername());

            LoginResponse response = new LoginResponse(jwt, savedUser);
            response.setRefreshToken(refreshToken);

            System.out.println("✅ Registration successful for user: " + request.getUsername());
            System.out.println("========== REGISTER SUCCESS ==========");
            
            return ResponseEntity.ok(response);

        } catch (Exception e) {
            System.out.println("❌ Registration error: " + e.getMessage());
            e.printStackTrace();
            return ResponseEntity.badRequest()
                .body(Map.of("message", "Error creating user: " + e.getMessage()));
        }
    }

    // ===================== LOGOUT =====================
    @PostMapping("/logout")
    public ResponseEntity<?> logout(@RequestBody Map<String, String> request) {
        try {
            String refreshToken = request.get("refreshToken");
            
            if (refreshToken != null) {
                refreshTokenStore.remove(refreshToken);
                System.out.println("✅ Removed refresh token");
            }
            
            HttpServletRequest httpRequest = ((ServletRequestAttributes) RequestContextHolder.currentRequestAttributes()).getRequest();
            String authHeader = httpRequest.getHeader("Authorization");
            
            if (authHeader != null && authHeader.startsWith("Bearer ")) {
                String token = authHeader.substring(7);
                Optional<UserSession> session = userSessionRepository.findBySessionToken(token);
                if (session.isPresent()) {
                    session.get().setActive(false);
                    userSessionRepository.save(session.get());
                    System.out.println("✅ Session deactivated");
                }
            }
            
            return ResponseEntity.ok(Map.of("message", "Logged out successfully"));

        } catch (Exception e) {
            return ResponseEntity.badRequest()
                .body(Map.of("error", "Logout failed: " + e.getMessage()));
        }
    }

    // ===================== CHECK USERNAME =====================
    @GetMapping("/check-username/{username}")
    public ResponseEntity<Map<String, Boolean>> checkUsernameAvailability(@PathVariable String username) {
        boolean exists = userService.findByUsername(username) != null;
        return ResponseEntity.ok(Map.of("available", !exists));
    }

    // ===================== CHECK TOKEN VALIDITY =====================
    @GetMapping("/validate")
    public ResponseEntity<?> validateToken(@RequestHeader(value = "Authorization", required = false) String authHeader) {
        try {
            if (authHeader == null || !authHeader.startsWith("Bearer ")) {
                return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
                    .body(Map.of("valid", false, "error", "Invalid authorization header"));
            }

            String token = authHeader.substring(7);
            String username = jwtService.extractUsername(token);
            
            if (username == null) {
                return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
                    .body(Map.of("valid", false, "error", "Invalid token"));
            }
            
            User user = userService.findByUsername(username);
            if (user == null) {
                return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
                    .body(Map.of("valid", false, "error", "User not found"));
            }

            return ResponseEntity.ok(Map.of(
                "valid", true,
                "username", username,
                "role", user.getRole()
            ));

        } catch (Exception e) {
            e.printStackTrace();
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
                .body(Map.of("valid", false, "error", e.getMessage()));
        }
    }

    // ===================== CONNECT GMAIL ACCOUNT =====================
    @PostMapping("/connect/google")
    public ResponseEntity<?> connectGoogleAccount(@RequestBody Map<String, String> request,
                                                  HttpServletRequest httpRequest) {
        try {
            String accessToken = request.get("accessToken");
            String email = request.get("email");
            
            Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
            String username = authentication.getName();
            User user = userService.findByUsername(username);
            
            user.setProvider("GOOGLE_CONNECTED");
            userService.saveUser(user);
            
            if (accessToken != null && !accessToken.isEmpty()) {
                gmailMonitorService.startMonitoring(user.getId(), accessToken);
                System.out.println("📧 Gmail monitoring started for user: " + username);
            }
            
            System.out.println("✅ Gmail connected for user: " + username + " with email: " + email);
            
            return ResponseEntity.ok(Map.of(
                "message", "Gmail account connected successfully",
                "email", email,
                "monitoring", true
            ));
            
        } catch (Exception e) {
            e.printStackTrace();
            return ResponseEntity.badRequest()
                .body(Map.of("error", e.getMessage()));
        }
    }

    // ===================== HELPER METHODS =====================

    private String getClientIp(HttpServletRequest request) {
        String ipAddress = request.getHeader("X-Forwarded-For");
        if (ipAddress == null || ipAddress.isEmpty()) {
            ipAddress = request.getRemoteAddr();
        }
        if ("0:0:0:0:0:0:0:1".equals(ipAddress)) {
            ipAddress = "127.0.0.1";
        }
        return ipAddress;
    }

    private Map<String, String> getLocationFromIp(String ip) {
        Map<String, String> location = new HashMap<>();
        
        location.put("country", "Unknown");
        location.put("city", "Unknown");
        location.put("lat", "0");
        location.put("lon", "0");
        
        if (ip.startsWith("192.168.") || ip.startsWith("10.") || ip.startsWith("127.") || ip.equals("0:0:0:0:0:0:0:1")) {
            location.put("country", "Local Network");
            location.put("city", "Local");
            return location;
        }
        
        try {
            String url = "http://ip-api.com/json/" + ip + "?fields=status,message,country,city,lat,lon";
            RestTemplate restTemplate = new RestTemplate();
            String response = restTemplate.getForObject(url, String.class);
            
            com.fasterxml.jackson.databind.ObjectMapper mapper = new com.fasterxml.jackson.databind.ObjectMapper();
            com.fasterxml.jackson.databind.JsonNode root = mapper.readTree(response);
            
            if (root.get("status").asText().equals("success")) {
                location.put("country", root.get("country").asText());
                location.put("city", root.get("city").asText());
                location.put("lat", root.get("lat").asText());
                location.put("lon", root.get("lon").asText());
            }
        } catch (Exception e) {
            System.out.println("⚠️ Could not get location for IP: " + ip);
        }
        return location;
    }

    private String getDeviceInfo(String userAgent) {
        if (userAgent == null) return "Unknown Device";
        
        String ua = userAgent.toLowerCase();
        
        if (ua.contains("iphone")) return "iPhone";
        if (ua.contains("ipad")) return "iPad";
        if (ua.contains("android")) return "Android Device";
        if (ua.contains("windows")) return "Windows PC";
        if (ua.contains("mac")) return "Mac";
        if (ua.contains("linux")) return "Linux PC";
        
        return "Unknown Device";
    }

    private String getOperatingSystem(String userAgent) {
        if (userAgent == null) return "Unknown OS";
        
        String ua = userAgent.toLowerCase();
        
        if (ua.contains("windows nt 10")) return "Windows 10";
        if (ua.contains("windows nt 11")) return "Windows 11";
        if (ua.contains("mac os x")) return "macOS";
        if (ua.contains("android")) return "Android";
        if (ua.contains("iphone")) return "iOS";
        if (ua.contains("linux")) return "Linux";
        
        return "Unknown OS";
    }

    private String getBrowserInfo(String userAgent) {
        if (userAgent == null) return "Unknown Browser";
        
        if (userAgent.contains("Chrome") && !userAgent.contains("Edg")) return "Chrome";
        if (userAgent.contains("Firefox")) return "Firefox";
        if (userAgent.contains("Safari") && !userAgent.contains("Chrome")) return "Safari";
        if (userAgent.contains("Edg")) return "Edge";
        
        return "Unknown Browser";
    }

    private boolean checkIfKnownDevice(Long userId, String deviceInfo, String ipAddress) {
        List<UserSession> previousSessions = userSessionRepository.findByUserIdOrderByLoginTimeDesc(userId);
        LocalDateTime thirtyDaysAgo = LocalDateTime.now().minusDays(30);
        
        for (UserSession session : previousSessions) {
            if (session.getLoginTime().isAfter(thirtyDaysAgo)) {
                if (session.getDeviceInfo().equals(deviceInfo)) {
                    return true;
                }
                if (session.getIpAddress().equals(ipAddress) && !ipAddress.startsWith("192.168.")) {
                    return true;
                }
            }
        }
        
        return false;
    }

    private void sendLoginAlertEmail(User user, String device, String location, String ip, 
                                     Map<String, String> locationData) {
        try {
            SimpleMailMessage message = new SimpleMailMessage();
            message.setTo(user.getEmail());
            message.setSubject("🔐 New Login Detected - " + LocalDateTime.now().format(DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm")));
            
            String locationEmoji = getLocationEmoji(locationData.get("country"));
            
            String emailBody = String.format(
                "Hello %s,\n\n" +
                "⚠️ **ALERT** A new login was detected on your account!\n\n" +
                "📍 **Location:** %s %s\n" +
                "🏙️ **City:** %s\n" +
                "💻 **Device:** %s\n" +
                "🌐 **IP Address:** %s\n" +
                "⏰ **Time:** %s\n\n" +
                "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n\n" +
                "If this was you, you can ignore this email.\n\n" +
                "If this WASN'T you, please secure your account immediately:\n" +
                "1️⃣ Login to your dashboard\n" +
                "2️⃣ Go to Login History page\n" +
                "3️⃣ Terminate this session\n" +
                "4️⃣ Change your password\n" +
                "5️⃣ Enable two-factor authentication\n\n" +
                "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n\n" +
                "Stay safe,\n" +
                "Cyber Threat Intelligence Team",
                user.getUsername(),
                locationEmoji,
                location,
                locationData.get("city"),
                device,
                ip,
                LocalDateTime.now().format(DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss"))
            );
            
            message.setText(emailBody);
            mailSender.send(message);
            
            System.out.println("✅ Alert email sent to: " + user.getEmail());
            
        } catch (Exception e) {
            System.out.println("❌ Failed to send email alert: " + e.getMessage());
            e.printStackTrace();
        }
    }

    private String getLocationEmoji(String country) {
        Map<String, String> emojiMap = new HashMap<>();
        emojiMap.put("India", "🇮🇳");
        emojiMap.put("United States", "🇺🇸");
        emojiMap.put("United Kingdom", "🇬🇧");
        emojiMap.put("Canada", "🇨🇦");
        emojiMap.put("Australia", "🇦🇺");
        emojiMap.put("Germany", "🇩🇪");
        emojiMap.put("France", "🇫🇷");
        emojiMap.put("Japan", "🇯🇵");
        emojiMap.put("China", "🇨🇳");
        emojiMap.put("Russia", "🇷🇺");
        emojiMap.put("Brazil", "🇧🇷");
        emojiMap.put("South Africa", "🇿🇦");
        emojiMap.put("Local Network", "🏠");
        
        return emojiMap.getOrDefault(country, "🌍");
    }
}