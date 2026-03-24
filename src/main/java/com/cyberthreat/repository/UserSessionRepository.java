package com.cyberthreat.repository;

import com.cyberthreat.model.UserSession;
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
public interface UserSessionRepository extends JpaRepository<UserSession, Long> {
    
    List<UserSession> findByUserIdOrderByLoginTimeDesc(Long userId);
    
    Optional<UserSession> findBySessionToken(String sessionToken);
    
    // FIXED: Use 'isActive' as the property name (matches getter isActive())
    @Modifying
    @Transactional
    @Query("UPDATE UserSession s SET s.isActive = false WHERE s.user.id = :userId AND s.id != :currentSessionId")
    int terminateOtherSessions(@Param("userId") Long userId, @Param("currentSessionId") Long currentSessionId);
    
    @Modifying
    @Transactional
    @Query("UPDATE UserSession s SET s.isActive = false WHERE s.user.id = :userId AND s.lastActivity < :cutoffDate")
    int deactivateOldSessions(@Param("userId") Long userId, @Param("cutoffDate") LocalDateTime cutoffDate);
    
    @Modifying
    @Transactional
    @Query("DELETE FROM UserSession s WHERE s.user.id = :userId AND s.lastActivity < :cutoffDate")
    int deleteOldSessions(@Param("userId") Long userId, @Param("cutoffDate") LocalDateTime cutoffDate);
}