package com.cyberthreat.service;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.mail.SimpleMailMessage;
import org.springframework.mail.javamail.JavaMailSender;
import org.springframework.messaging.simp.SimpMessagingTemplate;
import org.springframework.stereotype.Service;

import java.util.Map;

@Service
public class NotificationService {

    @Autowired
    private SimpMessagingTemplate messagingTemplate;

    @Autowired
    private JavaMailSender mailSender;

    public void sendToUser(String username, String destination, Object payload) {
        messagingTemplate.convertAndSendToUser(username, destination, payload);
    }

    public void sendToAll(String destination, Object payload) {
        messagingTemplate.convertAndSend(destination, payload);
    }

    public void sendEmail(String to, String subject, String content) {
        SimpleMailMessage message = new SimpleMailMessage();
        message.setTo(to);
        message.setSubject(subject);
        message.setText(content);
        mailSender.send(message);
    }

    public void sendGmailAlert(String username, String email, Map<String, Object> alertData) {
        // Send via WebSocket
        sendToUser(username, "/queue/gmail-alerts", alertData);
        
        // Send via Email
        String subject = "🔐 New Gmail Login Detected!";
        String content = String.format(
            "A new login was detected on your Gmail account.\n\n" +
            "Device: %s\n" +
            "Location: %s\n" +
            "Time: %s\n\n" +
            "If this wasn't you, please secure your account immediately.",
            alertData.get("deviceName"),
            alertData.get("location"),
            alertData.get("timestamp")
        );
        
        sendEmail(email, subject, content);
    }
}