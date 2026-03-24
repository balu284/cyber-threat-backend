package com.cyberthreat.repository;

import com.cyberthreat.model.GmailSession;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;
import org.springframework.transaction.annotation.Transactional;

import java.time.LocalDateTime;
import java.util.List;
import java.util.Optional;

@Repository
public interface GmailSessionRepository extends JpaRepository<GmailSession, Long> {
    
    List<GmailSession> findByUserIdOrderByLastSeenDesc(Long userId);
    
    Optional<GmailSession> findByUserIdAndDeviceId(Long userId, String deviceId);
    
    Optional<GmailSession> findBySessionId(String sessionId);
    
    @Query("SELECT s FROM GmailSession s WHERE s.user.id = :userId AND s.isVerified = false AND s.alertSent = false")
    List<GmailSession> findUnverifiedSessions(@Param("userId") Long userId);
    
    @Query("SELECT s FROM GmailSession s WHERE s.user.id = :userId AND s.isBlocked = true")
    List<GmailSession> findBlockedSessions(@Param("userId") Long userId);
    
    @Modifying
    @Transactional
    @Query("UPDATE GmailSession s SET s.isBlocked = true, s.blockReason = :reason WHERE s.id = :sessionId")
    int blockSession(@Param("sessionId") Long sessionId, @Param("reason") String reason);
    
    @Modifying
    @Transactional
    @Query("UPDATE GmailSession s SET s.isVerified = true WHERE s.user.id = :userId AND s.deviceId = :deviceId")
    int verifyDevice(@Param("userId") Long userId, @Param("deviceId") String deviceId);
    
    @Modifying
    @Transactional
    @Query("DELETE FROM GmailSession s WHERE s.user.id = :userId AND s.lastSeen < :cutoffDate")
    int deleteOldSessions(@Param("userId") Long userId, @Param("cutoffDate") LocalDateTime cutoffDate);
    
    boolean existsByUserIdAndDeviceId(Long userId, String deviceId);
    
    long countByUserIdAndIsVerifiedFalse(Long userId); // ADD THIS LINE
}