package com.cyberthreat.controller;

import org.springframework.core.io.Resource;
import org.springframework.core.io.UrlResource;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.HashMap;
import java.util.Map;

@RestController
@RequestMapping("/api/agent")
@CrossOrigin(origins = "http://localhost:4200")
public class AgentController {

    // Path where agent files are stored - UPDATED to your backend agents folder
    private final String AGENT_STORAGE_PATH = "C:/Users/balur/Downloads/cyber-threat-intelligence/agents/";

    @GetMapping("/download/{os}")
    public ResponseEntity<Resource> downloadAgent(@PathVariable String os) {
        try {
            String fileName;
            Path filePath;
            
            switch(os.toLowerCase()) {
                case "windows":
                    fileName = "CyberThreatAgent.exe";
                    filePath = Paths.get(AGENT_STORAGE_PATH + "windows/" + fileName);
                    break;
                case "mac":
                    fileName = "CyberThreatAgent.dmg";
                    filePath = Paths.get(AGENT_STORAGE_PATH + "mac/" + fileName);
                    break;
                case "linux":
                    fileName = "cyberthreat-agent.deb";
                    filePath = Paths.get(AGENT_STORAGE_PATH + "linux/" + fileName);
                    break;
                default:
                    return ResponseEntity.badRequest().build();
            }

            Resource resource = new UrlResource(filePath.toUri());
            
            if (!resource.exists()) {
                System.out.println("❌ File not found at: " + filePath.toString());
                return ResponseEntity.notFound().build();
            }

            System.out.println("✅ Sending file: " + fileName);
            
            return ResponseEntity.ok()
                .contentType(MediaType.APPLICATION_OCTET_STREAM)
                .header(HttpHeaders.CONTENT_DISPOSITION, "attachment; filename=\"" + fileName + "\"")
                .body(resource);

        } catch (Exception e) {
            e.printStackTrace();
            return ResponseEntity.internalServerError().build();
        }
    }

    @GetMapping("/info")
    public ResponseEntity<?> getAgentInfo() {
        Map<String, Object> info = new HashMap<>();
        info.put("version", "1.0.0");
        info.put("releaseDate", "2026-03-02");
        info.put("supportedOS", new String[]{"Windows 10/11", "macOS 11+", "Ubuntu 20.04+"});
        
        Map<String, String> fileSizes = new HashMap<>();
        fileSizes.put("windows", "16 MB");
        fileSizes.put("mac", "18 MB");
        fileSizes.put("linux", "12 MB");
        info.put("fileSizes", fileSizes);
        
        Map<String, Boolean> availability = new HashMap<>();
        availability.put("windows", checkFileExists("windows"));
        availability.put("mac", checkFileExists("mac"));
        availability.put("linux", checkFileExists("linux"));
        info.put("available", availability);
        
        return ResponseEntity.ok(info);
    }

    @GetMapping("/check")
    public ResponseEntity<?> checkAllFiles() {
        Map<String, Object> response = new HashMap<>();
        
        // Check Windows agent
        Path windowsPath = Paths.get(AGENT_STORAGE_PATH + "windows/CyberThreatAgent.exe");
        response.put("windows", Map.of(
            "exists", windowsPath.toFile().exists(),
            "path", windowsPath.toString(),
            "fileName", "CyberThreatAgent.exe",
            "size", windowsPath.toFile().exists() ? windowsPath.toFile().length() + " bytes" : "N/A"
        ));
        
        // Check Mac agent
        Path macPath = Paths.get(AGENT_STORAGE_PATH + "mac/CyberThreatAgent.dmg");
        response.put("mac", Map.of(
            "exists", macPath.toFile().exists(),
            "path", macPath.toString(),
            "fileName", "CyberThreatAgent.dmg"
        ));
        
        // Check Linux agent
        Path linuxPath = Paths.get(AGENT_STORAGE_PATH + "linux/cyberthreat-agent.deb");
        response.put("linux", Map.of(
            "exists", linuxPath.toFile().exists(),
            "path", linuxPath.toString(),
            "fileName", "cyberthreat-agent.deb"
        ));
        
        response.put("basePath", AGENT_STORAGE_PATH);
        response.put("timestamp", java.time.LocalDateTime.now().toString());
        
        return ResponseEntity.ok(response);
    }

    @GetMapping("/check-file")
    public ResponseEntity<?> checkFile(@RequestParam String os) {
        try {
            String fileName;
            Path filePath;
            
            switch(os.toLowerCase()) {
                case "windows":
                    fileName = "CyberThreatAgent.exe";
                    filePath = Paths.get(AGENT_STORAGE_PATH + "windows/" + fileName);
                    break;
                case "mac":
                    fileName = "CyberThreatAgent.dmg";
                    filePath = Paths.get(AGENT_STORAGE_PATH + "mac/" + fileName);
                    break;
                case "linux":
                    fileName = "cyberthreat-agent.deb";
                    filePath = Paths.get(AGENT_STORAGE_PATH + "linux/" + fileName);
                    break;
                default:
                    return ResponseEntity.badRequest().build();
            }

            boolean exists = filePath.toFile().exists();
            String absolutePath = filePath.toAbsolutePath().toString();
            long fileSize = exists ? filePath.toFile().length() : 0;
            
            return ResponseEntity.ok(Map.of(
                "os", os,
                "exists", exists,
                "path", absolutePath,
                "fileName", fileName,
                "fileSize", fileSize,
                "fileSizeMB", exists ? String.format("%.2f MB", fileSize / (1024.0 * 1024.0)) : "N/A",
                "message", exists ? "✅ File ready for " + os : "❌ File missing for " + os
            ));

        } catch (Exception e) {
            return ResponseEntity.ok(Map.of(
                "os", os,
                "error", e.getMessage(),
                "exists", false
            ));
        }
    }

    private boolean checkFileExists(String os) {
        try {
            String fileName;
            Path filePath;
            
            switch(os.toLowerCase()) {
                case "windows":
                    fileName = "CyberThreatAgent.exe";
                    filePath = Paths.get(AGENT_STORAGE_PATH + "windows/" + fileName);
                    break;
                case "mac":
                    fileName = "CyberThreatAgent.dmg";
                    filePath = Paths.get(AGENT_STORAGE_PATH + "mac/" + fileName);
                    break;
                case "linux":
                    fileName = "cyberthreat-agent.deb";
                    filePath = Paths.get(AGENT_STORAGE_PATH + "linux/" + fileName);
                    break;
                default:
                    return false;
            }
            return filePath.toFile().exists();
        } catch (Exception e) {
            return false;
        }
    }
}