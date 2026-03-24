package com.cyberthreat;

import org.junit.jupiter.api.Test;
import org.springframework.boot.test.context.SpringBootTest;

@SpringBootTest
class CyberThreatIntelligenceApplicationTest {

    @Test
    void contextLoads() {
        // This test verifies that the Spring application context loads successfully
    }

    @Test
    void mainMethodStartsApplication() {
        CyberThreatIntelligenceApplication.main(new String[] {});
    }
}