package com.cyberthreat.controller;

import com.cyberthreat.model.Device;
import com.cyberthreat.model.LocalThreatEvent;
import com.cyberthreat.model.User;
import com.cyberthreat.repository.DeviceRepository;
import com.cyberthreat.repository.LocalThreatEventRepository;
import com.cyberthreat.service.UserService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.web.bind.annotation.*;
import java.time.LocalDateTime;
import java.time.temporal.ChronoUnit;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.UUID;
import java.util.ArrayList;
import java.util.HashMap;

@RestController
@RequestMapping("/api/devices")
@CrossOrigin(origins = "http://localhost:4200", allowedHeaders = "*", methods = {RequestMethod.GET, RequestMethod.POST, RequestMethod.PUT, RequestMethod.DELETE, RequestMethod.PATCH, RequestMethod.OPTIONS})
public class DeviceController {

    @Autowired
    private DeviceRepository deviceRepository;

    @Autowired
    private LocalThreatEventRepository threatEventRepository;

    @Autowired
    private UserService userService;

    // Maximum number of threats that can be deleted in one bulk operation
    private static final int MAX_BULK_DELETE_LIMIT = 20;

    @GetMapping
    public ResponseEntity<?> getDevicesRoot() {
        return getUserDevices();
    }

    @GetMapping("/my-devices")
    public ResponseEntity<?> getUserDevices() {
        try {
            Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
            String username = authentication.getName();
            
            System.out.println("Getting devices for user: " + username);
            
            User user = userService.findByUsername(username);
            if (user == null) {
                return ResponseEntity.status(HttpStatus.NOT_FOUND)
                    .body(Map.of("error", "User not found"));
            }
            
            List<Device> devices = deviceRepository.findByUserId(user.getId());
            System.out.println("Found " + devices.size() + " devices");
            
            return ResponseEntity.ok(devices);
            
        } catch (Exception e) {
            e.printStackTrace();
            return ResponseEntity.status(HttpStatus.BAD_REQUEST)
                .body(Map.of("error", e.getMessage()));
        }
    }

    @PostMapping("/register")
    public ResponseEntity<?> registerDevice(@RequestBody Device device) {
        try {
            Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
            String username = authentication.getName();
            User user = userService.findByUsername(username);

            if (device.getDeviceId() == null || device.getDeviceId().isEmpty()) {
                device.setDeviceId(generateDeviceId());
            }

            Optional<Device> existingDevice = deviceRepository.findByDeviceId(device.getDeviceId());
            if (existingDevice.isPresent()) {
                return ResponseEntity.badRequest()
                    .body(Map.of("message", "Device already registered"));
            }

            device.setUser(user);
            device.setStatus(Device.DeviceStatus.ONLINE);
            device.setRegisteredAt(LocalDateTime.now());
            device.setLastSeen(LocalDateTime.now());

            Device savedDevice = deviceRepository.save(device);
            return ResponseEntity.ok(savedDevice);

        } catch (Exception e) {
            e.printStackTrace();
            return ResponseEntity.badRequest()
                .body(Map.of("message", "Error registering device", "error", e.getMessage()));
        }
    }

    @PostMapping("/{deviceId}/threat-event")
    public ResponseEntity<?> reportThreatEvent(
            @PathVariable String deviceId,
            @RequestBody LocalThreatEvent threatEvent) {
        
        try {
            Optional<Device> deviceOpt = deviceRepository.findByDeviceId(deviceId);
            if (deviceOpt.isEmpty()) {
                return ResponseEntity.badRequest()
                    .body(Map.of("message", "Device not found"));
            }

            Device device = deviceOpt.get();
            threatEvent.setDevice(device);
            threatEvent.setDetectedAt(LocalDateTime.now());

            LocalThreatEvent savedEvent = threatEventRepository.save(threatEvent);
            
            device.setLastSeen(LocalDateTime.now());
            deviceRepository.save(device);
            
            return ResponseEntity.ok(savedEvent);

        } catch (Exception e) {
            e.printStackTrace();
            return ResponseEntity.badRequest()
                .body(Map.of("message", "Error reporting threat event", "error", e.getMessage()));
        }
    }

    @GetMapping("/{deviceId}/threat-events")
    public ResponseEntity<?> getDeviceThreatEvents(@PathVariable String deviceId) {
        Optional<Device> deviceOpt = deviceRepository.findByDeviceId(deviceId);
        if (deviceOpt.isEmpty()) {
            return ResponseEntity.notFound().build();
        }

        Device device = deviceOpt.get();
        List<LocalThreatEvent> threatEvents = threatEventRepository.findByDeviceId(device.getId());
        return ResponseEntity.ok(threatEvents);
    }

    @GetMapping("/threat-events/my")
    public ResponseEntity<?> getUserThreatEvents() {
        try {
            Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
            String username = authentication.getName();
            User user = userService.findByUsername(username);
            List<LocalThreatEvent> threatEvents = threatEventRepository.findByDeviceUserId(user.getId());
            return ResponseEntity.ok(threatEvents);
        } catch (Exception e) {
            e.printStackTrace();
            return ResponseEntity.badRequest().body(Map.of("error", e.getMessage()));
        }
    }

    // ========== DEVICE MANAGEMENT METHODS ==========

    @DeleteMapping("/{deviceId}")
    @Transactional
    public ResponseEntity<?> deleteDevice(@PathVariable String deviceId) {
        try {
            Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
            String username = authentication.getName();
            User user = userService.findByUsername(username);
            
            Optional<Device> deviceOpt = deviceRepository.findByDeviceId(deviceId);
            if (deviceOpt.isEmpty()) {
                return ResponseEntity.status(HttpStatus.NOT_FOUND)
                    .body(Map.of("error", "Device not found"));
            }
            
            Device device = deviceOpt.get();
            
            if (!device.getUser().getId().equals(user.getId())) {
                return ResponseEntity.status(HttpStatus.FORBIDDEN)
                    .body(Map.of("error", "You don't have permission to delete this device"));
            }
            
            threatEventRepository.deleteByDeviceId(device.getId());
            deviceRepository.delete(device);
            
            System.out.println("✅ Device deleted: " + deviceId + " by user: " + username);
            
            return ResponseEntity.ok(Map.of(
                "message", "Device deleted successfully",
                "deviceId", deviceId
            ));
            
        } catch (Exception e) {
            e.printStackTrace();
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                .body(Map.of("error", "Failed to delete device: " + e.getMessage()));
        }
    }

    @PatchMapping("/{deviceId}/status")
    public ResponseEntity<?> updateDeviceStatus(
            @PathVariable String deviceId,
            @RequestBody Map<String, String> statusUpdate) {
        try {
            Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
            String username = authentication.getName();
            User user = userService.findByUsername(username);
            
            Optional<Device> deviceOpt = deviceRepository.findByDeviceId(deviceId);
            if (deviceOpt.isEmpty()) {
                return ResponseEntity.status(HttpStatus.NOT_FOUND)
                    .body(Map.of("error", "Device not found"));
            }
            
            Device device = deviceOpt.get();
            
            if (!device.getUser().getId().equals(user.getId())) {
                return ResponseEntity.status(HttpStatus.FORBIDDEN)
                    .body(Map.of("error", "You don't have permission to update this device"));
            }
            
            String newStatus = statusUpdate.get("status");
            if (newStatus == null || newStatus.isEmpty()) {
                return ResponseEntity.badRequest()
                    .body(Map.of("error", "Status is required"));
            }
            
            try {
                device.setStatus(Device.DeviceStatus.valueOf(newStatus));
            } catch (IllegalArgumentException e) {
                return ResponseEntity.badRequest()
                    .body(Map.of("error", "Invalid status value. Use: ONLINE, OFFLINE, or SUSPENDED"));
            }
            
            device.setLastSeen(LocalDateTime.now());
            Device updatedDevice = deviceRepository.save(device);
            
            System.out.println("✅ Device status updated: " + deviceId + " -> " + newStatus);
            
            return ResponseEntity.ok(updatedDevice);
            
        } catch (Exception e) {
            e.printStackTrace();
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                .body(Map.of("error", "Failed to update device status: " + e.getMessage()));
        }
    }

    @PostMapping("/{deviceId}/unregister")
    public ResponseEntity<?> unregisterDevice(@PathVariable String deviceId) {
        return deleteDevice(deviceId);
    }

    // ========== SINGLE THREAT MANAGEMENT METHODS ==========

    @DeleteMapping("/threats/{threatId}")
    public ResponseEntity<?> deleteThreat(@PathVariable Long threatId) {
        try {
            Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
            String username = authentication.getName();
            User user = userService.findByUsername(username);
            
            Optional<LocalThreatEvent> threatOpt = threatEventRepository.findById(threatId);
            if (threatOpt.isEmpty()) {
                return ResponseEntity.status(HttpStatus.NOT_FOUND)
                    .body(Map.of("error", "Threat not found"));
            }
            
            LocalThreatEvent threat = threatOpt.get();
            
            // Verify the threat belongs to a device owned by this user
            if (threat.getDevice() == null || 
                threat.getDevice().getUser() == null || 
                !threat.getDevice().getUser().getId().equals(user.getId())) {
                return ResponseEntity.status(HttpStatus.FORBIDDEN)
                    .body(Map.of("error", "Not authorized to delete this threat"));
            }
            
            threatEventRepository.delete(threat);
            
            return ResponseEntity.ok(Map.of(
                "message", "Threat deleted successfully",
                "id", threatId
            ));
            
        } catch (Exception e) {
            e.printStackTrace();
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                .body(Map.of("error", "Failed to delete threat: " + e.getMessage()));
        }
    }

    @PutMapping("/threats/{threatId}")
    public ResponseEntity<?> updateThreat(@PathVariable Long threatId, @RequestBody LocalThreatEvent updatedThreat) {
        try {
            Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
            String username = authentication.getName();
            User user = userService.findByUsername(username);
            
            Optional<LocalThreatEvent> threatOpt = threatEventRepository.findById(threatId);
            if (threatOpt.isEmpty()) {
                return ResponseEntity.status(HttpStatus.NOT_FOUND)
                    .body(Map.of("error", "Threat not found"));
            }
            
            LocalThreatEvent threat = threatOpt.get();
            
            // Verify the threat belongs to a device owned by this user
            if (threat.getDevice() == null || 
                threat.getDevice().getUser() == null || 
                !threat.getDevice().getUser().getId().equals(user.getId())) {
                return ResponseEntity.status(HttpStatus.FORBIDDEN)
                    .body(Map.of("error", "Not authorized to update this threat"));
            }
            
            // Update fields
            threat.setResolved(updatedThreat.isResolved());
            if (updatedThreat.getDescription() != null) {
                threat.setDescription(updatedThreat.getDescription());
            }
            
            LocalThreatEvent savedThreat = threatEventRepository.save(threat);
            
            return ResponseEntity.ok(savedThreat);
            
        } catch (Exception e) {
            e.printStackTrace();
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                .body(Map.of("error", "Failed to update threat: " + e.getMessage()));
        }
    }

    // ========== BULK THREAT MANAGEMENT METHODS WITH 20 LIMIT ==========

    @PostMapping("/threats/bulk-delete")
    @Transactional
    public ResponseEntity<?> bulkDeleteThreats(@RequestBody Map<String, List<Long>> request) {
        try {
            Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
            String username = authentication.getName();
            User user = userService.findByUsername(username);
            
            if (user == null) {
                return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
                    .body(Map.of("error", "User not found"));
            }
            
            List<Long> threatIds = request.get("threatIds");
            if (threatIds == null || threatIds.isEmpty()) {
                return ResponseEntity.badRequest()
                    .body(Map.of("error", "No threat IDs provided"));
            }
            
            // ✅ NEW: Check if exceeding maximum limit
            if (threatIds.size() > MAX_BULK_DELETE_LIMIT) {
                return ResponseEntity.status(HttpStatus.BAD_REQUEST)
                    .body(Map.of(
                        "error", "Maximum " + MAX_BULK_DELETE_LIMIT + " threats can be deleted at once",
                        "requested", threatIds.size(),
                        "maxLimit", MAX_BULK_DELETE_LIMIT
                    ));
            }
            
            System.out.println("Bulk delete request for " + threatIds.size() + " threats by user: " + username);
            System.out.println("Threat IDs: " + threatIds);
            
            int deletedCount = 0;
            List<Long> failedIds = new ArrayList<>();
            List<Map<String, Object>> errors = new ArrayList<>();
            
            for (Long threatId : threatIds) {
                try {
                    Optional<LocalThreatEvent> threatOpt = threatEventRepository.findById(threatId);
                    if (threatOpt.isPresent()) {
                        LocalThreatEvent threat = threatOpt.get();
                        
                        // Verify the threat belongs to a device owned by this user
                        if (threat.getDevice() != null && 
                            threat.getDevice().getUser() != null && 
                            threat.getDevice().getUser().getId().equals(user.getId())) {
                            
                            threatEventRepository.delete(threat);
                            deletedCount++;
                            System.out.println("✅ Deleted threat ID: " + threatId);
                        } else {
                            failedIds.add(threatId);
                            errors.add(Map.of(
                                "id", threatId,
                                "reason", "Not authorized to delete this threat"
                            ));
                            System.out.println("❌ Not authorized to delete threat ID: " + threatId);
                        }
                    } else {
                        failedIds.add(threatId);
                        errors.add(Map.of(
                            "id", threatId,
                            "reason", "Threat not found"
                        ));
                        System.out.println("❌ Threat not found ID: " + threatId);
                    }
                } catch (Exception e) {
                    failedIds.add(threatId);
                    errors.add(Map.of(
                        "id", threatId,
                        "reason", e.getMessage()
                    ));
                    System.err.println("❌ Error deleting threat " + threatId + ": " + e.getMessage());
                    e.printStackTrace();
                }
            }
            
            Map<String, Object> response = new HashMap<>();
            response.put("message", "Bulk delete completed");
            response.put("deletedCount", deletedCount);
            response.put("failedIds", failedIds);
            response.put("errors", errors);
            response.put("totalRequested", threatIds.size());
            response.put("maxLimit", MAX_BULK_DELETE_LIMIT);
            
            if (deletedCount > 0) {
                return ResponseEntity.ok(response);
            } else {
                return ResponseEntity.status(HttpStatus.BAD_REQUEST)
                    .body(response);
            }
            
        } catch (Exception e) {
            e.printStackTrace();
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                .body(Map.of(
                    "error", "Failed to bulk delete threats: " + e.getMessage()
                ));
        }
    }

    @PostMapping("/threats/bulk-resolve")
    @Transactional
    public ResponseEntity<?> bulkResolveThreats(@RequestBody Map<String, List<Long>> request) {
        try {
            Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
            String username = authentication.getName();
            User user = userService.findByUsername(username);
            
            if (user == null) {
                return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
                    .body(Map.of("error", "User not found"));
            }
            
            List<Long> threatIds = request.get("threatIds");
            if (threatIds == null || threatIds.isEmpty()) {
                return ResponseEntity.badRequest()
                    .body(Map.of("error", "No threat IDs provided"));
            }
            
            // ✅ NEW: Check if exceeding maximum limit
            if (threatIds.size() > MAX_BULK_DELETE_LIMIT) {
                return ResponseEntity.status(HttpStatus.BAD_REQUEST)
                    .body(Map.of(
                        "error", "Maximum " + MAX_BULK_DELETE_LIMIT + " threats can be resolved at once",
                        "requested", threatIds.size(),
                        "maxLimit", MAX_BULK_DELETE_LIMIT
                    ));
            }
            
            System.out.println("Bulk resolve request for " + threatIds.size() + " threats by user: " + username);
            
            int resolvedCount = 0;
            List<Long> failedIds = new ArrayList<>();
            List<Map<String, Object>> errors = new ArrayList<>();
            
            for (Long threatId : threatIds) {
                try {
                    Optional<LocalThreatEvent> threatOpt = threatEventRepository.findById(threatId);
                    if (threatOpt.isPresent()) {
                        LocalThreatEvent threat = threatOpt.get();
                        
                        // Verify ownership
                        if (threat.getDevice() != null && 
                            threat.getDevice().getUser() != null && 
                            threat.getDevice().getUser().getId().equals(user.getId())) {
                            
                            threat.setResolved(true);
                            threatEventRepository.save(threat);
                            resolvedCount++;
                            System.out.println("✅ Resolved threat ID: " + threatId);
                        } else {
                            failedIds.add(threatId);
                            errors.add(Map.of(
                                "id", threatId,
                                "reason", "Not authorized to resolve this threat"
                            ));
                            System.out.println("❌ Not authorized to resolve threat ID: " + threatId);
                        }
                    } else {
                        failedIds.add(threatId);
                        errors.add(Map.of(
                            "id", threatId,
                            "reason", "Threat not found"
                        ));
                        System.out.println("❌ Threat not found ID: " + threatId);
                    }
                } catch (Exception e) {
                    failedIds.add(threatId);
                    errors.add(Map.of(
                        "id", threatId,
                        "reason", e.getMessage()
                    ));
                    System.err.println("❌ Error resolving threat " + threatId + ": " + e.getMessage());
                    e.printStackTrace();
                }
            }
            
            Map<String, Object> response = new HashMap<>();
            response.put("message", "Bulk resolve completed");
            response.put("resolvedCount", resolvedCount);
            response.put("failedIds", failedIds);
            response.put("errors", errors);
            response.put("totalRequested", threatIds.size());
            response.put("maxLimit", MAX_BULK_DELETE_LIMIT);
            
            return ResponseEntity.ok(response);
            
        } catch (Exception e) {
            e.printStackTrace();
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                .body(Map.of("error", "Failed to bulk resolve threats: " + e.getMessage()));
        }
    }

    @DeleteMapping("/{deviceId}/threats/old")
    @Transactional
    public ResponseEntity<?> deleteOldThreats(
            @PathVariable String deviceId,
            @RequestParam int days) {
        try {
            Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
            String username = authentication.getName();
            User user = userService.findByUsername(username);
            
            Optional<Device> deviceOpt = deviceRepository.findByDeviceId(deviceId);
            if (deviceOpt.isEmpty()) {
                return ResponseEntity.status(HttpStatus.NOT_FOUND)
                    .body(Map.of("error", "Device not found"));
            }
            
            Device device = deviceOpt.get();
            
            // Verify ownership
            if (!device.getUser().getId().equals(user.getId())) {
                return ResponseEntity.status(HttpStatus.FORBIDDEN)
                    .body(Map.of("error", "Not authorized to delete threats from this device"));
            }
            
            LocalDateTime cutoffDate = LocalDateTime.now().minus(days, ChronoUnit.DAYS);
            
            int deletedCount = threatEventRepository.deleteOldThreats(device.getId(), cutoffDate);
            
            return ResponseEntity.ok(Map.of(
                "message", "Old threats deleted successfully",
                "deletedCount", deletedCount,
                "days", days
            ));
            
        } catch (Exception e) {
            e.printStackTrace();
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                .body(Map.of("error", "Failed to delete old threats: " + e.getMessage()));
        }
    }

    private String generateDeviceId() {
        return "DEV-" + UUID.randomUUID().toString().substring(0, 8).toUpperCase();
    }
}