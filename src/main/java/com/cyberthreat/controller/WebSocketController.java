package com.cyberthreat.controller;

import com.cyberthreat.model.GlobalThreatIndicator;
import com.cyberthreat.service.ThreatIntelligenceService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.messaging.handler.annotation.MessageMapping;
import org.springframework.messaging.handler.annotation.SendTo;
import org.springframework.messaging.simp.SimpMessagingTemplate;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Controller;
import java.time.LocalDateTime;
import java.util.HashMap;
import java.util.Map;

@Controller
public class WebSocketController {

    @Autowired
    private SimpMessagingTemplate messagingTemplate;

    @Autowired
    private ThreatIntelligenceService threatService;

    @MessageMapping("/threats.subscribe")
    @SendTo("/topic/threats")
    public Map<String, Object> subscribeToThreats() {
        Map<String, Object> response = new HashMap<>();
        response.put("type", "INITIAL_DATA");
        response.put("threatCount", threatService.getActiveThreats().size());
        response.put("timestamp", LocalDateTime.now());
        return response;
    }

    @Scheduled(fixedRate = 30000) // Every 30 seconds
    public void sendThreatUpdates() {
        Map<String, Object> update = new HashMap<>();
        update.put("type", "STATUS_UPDATE");
        update.put("activeThreats", threatService.getActiveThreats().size());
        update.put("lastUpdate", LocalDateTime.now());
        update.put("message", "Threat database updated");
        
        messagingTemplate.convertAndSend("/topic/threats", update);
    }

    public void notifyNewThreat(GlobalThreatIndicator threat) {
        Map<String, Object> notification = new HashMap<>();
        notification.put("type", "NEW_THREAT");
        notification.put("threat", threat);
        notification.put("timestamp", LocalDateTime.now());
        notification.put("alert", true);
        
        messagingTemplate.convertAndSend("/topic/threat-alerts", notification);
    }
}