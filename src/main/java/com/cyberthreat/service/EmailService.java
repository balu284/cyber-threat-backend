package com.cyberthreat.service;

import org.springframework.stereotype.Service;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import java.util.Map;

@Service
public class EmailService {

    private static final Logger log = LoggerFactory.getLogger(EmailService.class);

    // Remove all @Autowired dependencies - we'll use this as a stub service
    // Email functionality can be added later

    public void sendSimpleMessage(String to, String subject, String text) {
        log.info("Email service stub - would send to: {}, Subject: {}, Text: {}", to, subject, text);
    }

    public void sendThreatAlert(String to, String deviceName, String threatType, String indicator) {
        log.info("Threat alert email stub - Device: {}, Threat: {}, Indicator: {}", deviceName, threatType, indicator);
    }

    public void sendWeeklyReport(String to, String username, Map<String, Object> stats) {
        log.info("Weekly report email stub - User: {}, Stats: {}", username, stats);
    }
}