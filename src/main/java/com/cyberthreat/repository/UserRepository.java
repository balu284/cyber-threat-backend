package com.cyberthreat.repository;

import com.cyberthreat.model.User;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.stereotype.Repository;

import java.util.List;
import java.util.Optional;

@Repository
public interface UserRepository extends JpaRepository<User, Long> {
    
    Optional<User> findByUsername(String username);
    
    Optional<User> findByEmail(String email); // ✅ ADD THIS
    
    Boolean existsByUsername(String username);
    
    Boolean existsByEmail(String email);
    @Query("SELECT u FROM User u WHERE u.gmailConnected = true AND u.gmailAccessToken IS NOT NULL")
    List<User> findAllWithGmailConnected();
}
