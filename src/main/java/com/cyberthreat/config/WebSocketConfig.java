package com.cyberthreat.config;

import org.springframework.context.annotation.Configuration;
import org.springframework.messaging.simp.config.MessageBrokerRegistry;
import org.springframework.web.socket.config.annotation.EnableWebSocketMessageBroker;
import org.springframework.web.socket.config.annotation.StompEndpointRegistry;
import org.springframework.web.socket.config.annotation.WebSocketMessageBrokerConfigurer;

@Configuration
@EnableWebSocketMessageBroker
public class WebSocketConfig implements WebSocketMessageBrokerConfigurer {

    @Override
    public void configureMessageBroker(MessageBrokerRegistry config) {
        // Enable simple broker for topics, queues, and user-specific messages
        config.enableSimpleBroker("/topic", "/queue", "/user");
        
        // Set prefix for messages sent from client to server
        config.setApplicationDestinationPrefixes("/app");
        
        // Set prefix for user-specific messages
        config.setUserDestinationPrefix("/user");
    }

    @Override
    public void registerStompEndpoints(StompEndpointRegistry registry) {
        // Register WebSocket endpoint with SockJS fallback
        registry.addEndpoint("/ws-threat-intel")
                .setAllowedOriginPatterns("http://localhost:4200", "http://localhost:4201", "http://127.0.0.1:4200")
                .withSockJS()
                .setClientLibraryUrl("https://cdn.jsdelivr.net/npm/sockjs-client@1/dist/sockjs.min.js")
                .setHeartbeatTime(25000)
                .setDisconnectDelay(5000)
                .setSessionCookieNeeded(false);
        
        // Also add pure WebSocket endpoint (no SockJS)
        registry.addEndpoint("/ws-threat-intel")
                .setAllowedOriginPatterns("http://localhost:4200", "http://localhost:4201", "http://127.0.0.1:4200");
    }
}