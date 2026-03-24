package com.cyberthreat;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.scheduling.annotation.EnableScheduling;

@SpringBootApplication
@EnableScheduling
public class CyberThreatIntelligenceApplication {

    public static void main(String[] args) {
        SpringApplication.run(CyberThreatIntelligenceApplication.class, args);
    }
}