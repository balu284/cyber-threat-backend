package com.cyberthreat.repository;

import com.cyberthreat.model.LocalThreatEvent;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;
import org.springframework.transaction.annotation.Transactional;

import java.time.LocalDateTime;
import java.util.List;

@Repository
public interface LocalThreatEventRepository extends JpaRepository<LocalThreatEvent, Long> {
    
    List<LocalThreatEvent> findByDeviceId(Long deviceId);
    
    List<LocalThreatEvent> findByDeviceUserId(Long userId);
    
    long countByResolvedFalse();
    
    @Modifying
    @Transactional
    @Query("DELETE FROM LocalThreatEvent e WHERE e.device.id = :deviceId")
    void deleteByDeviceId(@Param("deviceId") Long deviceId);
    
    // Add this method for deleting old threats
    @Modifying
    @Transactional
    @Query("DELETE FROM LocalThreatEvent e WHERE e.device.id = :deviceId AND e.detectedAt < :cutoffDate")
    int deleteOldThreats(@Param("deviceId") Long deviceId, @Param("cutoffDate") LocalDateTime cutoffDate);
}