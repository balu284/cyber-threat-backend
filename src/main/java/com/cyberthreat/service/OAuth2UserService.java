package com.cyberthreat.service;

import com.cyberthreat.model.User;
import com.cyberthreat.repository.UserRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.oauth2.client.userinfo.DefaultOAuth2UserService;
import org.springframework.security.oauth2.client.userinfo.OAuth2UserRequest;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.user.DefaultOAuth2User;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.LocalDateTime;
import java.util.Collections;
import java.util.Map;
import java.util.Optional;
import java.util.UUID;

@Service
public class OAuth2UserService extends DefaultOAuth2UserService {

    @Autowired
    private UserRepository userRepository;

    @Override
    @Transactional
    public OAuth2User loadUser(OAuth2UserRequest userRequest) throws OAuth2AuthenticationException {
        OAuth2User oauth2User = super.loadUser(userRequest);
        
        Map<String, Object> attributes = oauth2User.getAttributes();
        
        // Log attributes for debugging
        System.out.println("========== GOOGLE OAUTH ATTRIBUTES ==========");
        attributes.forEach((key, value) -> System.out.println(key + ": " + value));
        
        // Extract user info from Google
        String email = (String) attributes.get("email");
        String name = (String) attributes.get("name");
        String firstName = (String) attributes.getOrDefault("given_name", "");
        String lastName = (String) attributes.getOrDefault("family_name", "");
        String googleId = (String) attributes.get("sub");
        String pictureUrl = (String) attributes.get("picture");
        Boolean emailVerified = (Boolean) attributes.getOrDefault("email_verified", false);
        
        if (email == null) {
            throw new OAuth2AuthenticationException("Email not found from Google");
        }
        
        // Check if user exists
        Optional<User> existingUser = userRepository.findByEmail(email);
        User user;
        
        if (existingUser.isPresent()) {
            user = existingUser.get();
            user.setLastLogin(LocalDateTime.now());
            user.setGoogleId(googleId);
            user.setPictureUrl(pictureUrl);
            user.setEmailVerified(emailVerified);
            userRepository.save(user);
            System.out.println("✅ Existing user logged in: " + email);
        } else {
            // Create new user - WITHOUT password (OAuth users don't need password)
            user = new User();
            
            // Generate username from email or use part before @
            String username = email.split("@")[0];
            
            // Check if username exists, if so append random string
            if (userRepository.findByUsername(username).isPresent()) {
                username = username + UUID.randomUUID().toString().substring(0, 5);
            }
            
            user.setUsername(username);
            user.setEmail(email);
            user.setFirstName(firstName != null ? firstName : name);
            user.setLastName(lastName != null ? lastName : "");
            // No password needed for OAuth users
            user.setPassword(null);
            user.setRole(User.UserRole.ROLE_USER);
            user.setEnabled(true);
            user.setCreatedAt(LocalDateTime.now());
            user.setLastLogin(LocalDateTime.now());
            user.setGoogleId(googleId);
            user.setPictureUrl(pictureUrl);
            user.setEmailVerified(emailVerified);
            user.setProvider("GOOGLE");
            
            user = userRepository.save(user);
            System.out.println("✅ New user created via Google OAuth: " + email);
        }
        
        // Return OAuth2User with authorities
        return new DefaultOAuth2User(
            Collections.singleton(new SimpleGrantedAuthority("ROLE_USER")),
            attributes,
            "email"
        );
    }
}