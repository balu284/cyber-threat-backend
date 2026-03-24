package com.cyberthreat.controller;

import com.cyberthreat.dto.ThreatIndicatorDTO;
import com.cyberthreat.model.GlobalThreatIndicator;
import com.cyberthreat.service.ThreatIntelligenceService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.data.domain.PageRequest;
import org.springframework.data.domain.Pageable;
import org.springframework.data.domain.Sort;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.*;

import java.time.LocalDateTime;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

@RestController
@RequestMapping("/api/threat-intelligence")
@CrossOrigin(origins = "http://localhost:4200")
public class ThreatIntelligenceController {

    @Autowired
    private ThreatIntelligenceService threatIntelligenceService;

    // ======================= ACTIVE THREATS =======================

    @GetMapping("/active-threats")
    public ResponseEntity<Map<String, Object>> getActiveThreats(
            @RequestParam(defaultValue = "0") int page,
            @RequestParam(defaultValue = "20") int size,
            @RequestParam(defaultValue = "lastSeen") String sortBy,
            @RequestParam(defaultValue = "desc") String direction) {

        Sort sort = direction.equalsIgnoreCase("desc")
                ? Sort.by(sortBy).descending()
                : Sort.by(sortBy).ascending();

        Pageable pageable = PageRequest.of(page, size, sort);

        // READ-ONLY call – no updates allowed here
        List<GlobalThreatIndicator> allThreats =
                threatIntelligenceService.getActiveThreats();

        int start = Math.min((int) pageable.getOffset(), allThreats.size());
        int end = Math.min(start + pageable.getPageSize(), allThreats.size());

        List<ThreatIndicatorDTO> threatDTOs = allThreats
                .subList(start, end)
                .stream()
                .map(ThreatIndicatorDTO::new)
                .collect(Collectors.toList());

        return ResponseEntity.ok(Map.of(
                "threats", threatDTOs,
                "currentPage", page,
                "totalItems", allThreats.size(),
                "totalPages", (int) Math.ceil((double) allThreats.size() / size)
        ));
    }

    // ======================= FILTERING =======================

    @GetMapping("/threats-by-type/{type}")
    public ResponseEntity<List<ThreatIndicatorDTO>> getThreatsByType(
            @PathVariable GlobalThreatIndicator.IndicatorType type) {

        List<ThreatIndicatorDTO> result = threatIntelligenceService
                .getThreatsByType(type)
                .stream()
                .map(ThreatIndicatorDTO::new)
                .collect(Collectors.toList());

        return ResponseEntity.ok(result);
    }

    @GetMapping("/threats-by-severity/{severity}")
    public ResponseEntity<List<ThreatIndicatorDTO>> getThreatsBySeverity(
            @PathVariable GlobalThreatIndicator.ThreatSeverity severity) {

        List<ThreatIndicatorDTO> result = threatIntelligenceService
                .getThreatsBySeverity(severity)
                .stream()
                .map(ThreatIndicatorDTO::new)
                .collect(Collectors.toList());

        return ResponseEntity.ok(result);
    }

    // ======================= INDICATOR CHECK =======================

    @GetMapping("/check-indicator")
    public ResponseEntity<Map<String, Object>> checkIndicator(
            @RequestParam String indicator,
            @RequestParam GlobalThreatIndicator.IndicatorType type) {

        boolean isMalicious =
                threatIntelligenceService.isIndicatorMalicious(indicator, type);

        return ResponseEntity.ok(Map.of(
                "indicator", indicator,
                "type", type,
                "isMalicious", isMalicious,
                "message", isMalicious
                        ? "⚠️ This indicator is known to be malicious"
                        : "✅ No threats found for this indicator",
                "timestamp", LocalDateTime.now()
        ));
    }

    // ======================= STATISTICS =======================

    @GetMapping("/stats")
    public ResponseEntity<Map<String, Object>> getThreatStats() {

        return ResponseEntity.ok(Map.of(
                "statistics", threatIntelligenceService.getThreatStatistics(),
                "lastUpdated", LocalDateTime.now(),
                "sources", List.of(
                        "Abuse.ch",
                        "URLhaus",
                        "Blocklist.de",
                        "OpenPhish"
                )
        ));
    }

    // ======================= SEARCH =======================

    @GetMapping("/search")
    public ResponseEntity<List<ThreatIndicatorDTO>> searchThreats(
            @RequestParam String query) {

        String q = query.toLowerCase();

        List<ThreatIndicatorDTO> result =
                threatIntelligenceService.getActiveThreats()
                        .stream()
                        .filter(t ->
                                (t.getIndicator() != null && t.getIndicator().toLowerCase().contains(q)) ||
                                (t.getDescription() != null && t.getDescription().toLowerCase().contains(q))
                        )
                        .map(ThreatIndicatorDTO::new)
                        .collect(Collectors.toList());

        return ResponseEntity.ok(result);
    }

    // ======================= ADMIN =======================

    @PostMapping("/refresh")
    @PreAuthorize("hasRole('ADMIN')")
    public ResponseEntity<Map<String, String>> refreshThreatData() {

        threatIntelligenceService.fetchThreatIntelligence();

        return ResponseEntity.ok(Map.of(
                "message", "Threat intelligence data refresh started",
                "timestamp", LocalDateTime.now().toString()
        ));
    }

    // ======================= SOURCES =======================

    @GetMapping("/sources")
    public ResponseEntity<Map<String, Object>> getThreatSources() {

        return ResponseEntity.ok(Map.of(
                "availableSources", List.of(
                        Map.of("name", "Abuse.ch Feodo Tracker", "type", "IP Blocklist", "url", "https://feodotracker.abuse.ch"),
                        Map.of("name", "URLhaus", "type", "Malicious URLs", "url", "https://urlhaus.abuse.ch"),
                        Map.of("name", "Blocklist.de", "type", "Multiple Threat Types", "url", "https://www.blocklist.de"),
                        Map.of("name", "OpenPhish", "type", "Phishing URLs", "url", "https://openphish.com")
                ),
                "lastSync", LocalDateTime.now()
        ));
    }
}
