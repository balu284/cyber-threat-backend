package com.cyberthreat.repository;

import com.cyberthreat.model.ThreatFeed;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;
import java.util.List;

@Repository
public interface ThreatFeedRepository extends JpaRepository<ThreatFeed, Long> {
    List<ThreatFeed> findByEnabledTrue();
}