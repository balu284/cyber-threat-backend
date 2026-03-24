package com.cyberthreat.config;

import com.cyberthreat.model.User;
import com.cyberthreat.model.ThreatFeed;
import com.cyberthreat.repository.UserRepository;
import com.cyberthreat.repository.ThreatFeedRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.CommandLineRunner;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Component;

@Component
public class DataInitializer implements CommandLineRunner {

    @Autowired
    private UserRepository userRepository;

    @Autowired
    private ThreatFeedRepository threatFeedRepository;

    @Autowired
    private PasswordEncoder passwordEncoder;

    @Override
    public void run(String... args) throws Exception {
        initializeUsers();
        initializeThreatFeeds();
    }

    private void initializeUsers() {
        if (userRepository.count() == 0) {
            // Create admin user
            User admin = new User();
            admin.setUsername("admin");
            admin.setPassword(passwordEncoder.encode("admin123"));
            admin.setEmail("admin@cyberthreat.com");
            admin.setFirstName("System");
            admin.setLastName("Administrator");
            admin.setRole(User.UserRole.ROLE_ADMIN);
            userRepository.save(admin);

            // Create regular user
            User user = new User();
            user.setUsername("user");
            user.setPassword(passwordEncoder.encode("user123"));
            user.setEmail("user@cyberthreat.com");
            user.setFirstName("Regular");
            user.setLastName("User");
            user.setRole(User.UserRole.ROLE_USER);
            userRepository.save(user);

            System.out.println("Sample users created:");
            System.out.println("Admin - username: admin, password: admin123");
            System.out.println("User - username: user, password: user123");
        }
    }

    private void initializeThreatFeeds() {
        if (threatFeedRepository.count() == 0) {
            // Free threat intelligence feeds
            ThreatFeed alienVault = new ThreatFeed();
            alienVault.setName("AlienVault OTX");
            alienVault.setDescription("Open Threat Exchange - Community powered threat intelligence");
            alienVault.setFeedUrl("https://otx.alienvault.com/api/v1/indicators/export");
            alienVault.setType(ThreatFeed.FeedType.FREE);
            alienVault.setEnabled(true);
            alienVault.setUpdateIntervalMinutes(120);
            threatFeedRepository.save(alienVault);

            ThreatFeed abuse_ch = new ThreatFeed();
            abuse_ch.setName("Abuse.ch");
            abuse_ch.setDescription("Fighting malware and botnets");
            abuse_ch.setFeedUrl("https://feodotracker.abuse.ch/downloads/ipblocklist.json");
            abuse_ch.setType(ThreatFeed.FeedType.FREE);
            abuse_ch.setEnabled(true);
            abuse_ch.setUpdateIntervalMinutes(180);
            threatFeedRepository.save(abuse_ch);

            System.out.println("Sample threat feeds initialized");
        }
    }
}