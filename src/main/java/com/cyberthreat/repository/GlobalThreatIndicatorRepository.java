package com.cyberthreat.repository;

import com.cyberthreat.model.GlobalThreatIndicator;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;
import org.springframework.transaction.annotation.Transactional;

import java.time.LocalDateTime;
import java.util.List;

@Repository
public interface GlobalThreatIndicatorRepository extends JpaRepository<GlobalThreatIndicator, Long> {
    List<GlobalThreatIndicator> findByActiveTrue();
    List<GlobalThreatIndicator> findByTypeAndActiveTrue(GlobalThreatIndicator.IndicatorType type);
    List<GlobalThreatIndicator> findBySeverityAndActiveTrue(GlobalThreatIndicator.ThreatSeverity severity);
    
    @Query("SELECT g FROM GlobalThreatIndicator g WHERE g.indicator = :indicator AND g.active = true")
    List<GlobalThreatIndicator> findByIndicatorValue(String indicator);
    
    long countByActiveTrue();
    
    boolean existsByIndicatorAndType(String indicator, GlobalThreatIndicator.IndicatorType type);
    
    // Add this method for auto-cleanup
    @Modifying
    @Transactional
    @Query("DELETE FROM GlobalThreatIndicator g WHERE g.lastSeen < :cutoffDate")
    int deleteThreatsOlderThan(@Param("cutoffDate") LocalDateTime cutoffDate);
}