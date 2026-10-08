package com.sarvatobhadra.backend.analyst;

import com.sarvatobhadra.backend.bluf.BlufReport;
import com.sarvatobhadra.backend.bluf.BlufRepository;
import com.sarvatobhadra.backend.common.enums.FeedbackStatus;
import com.sarvatobhadra.backend.threat.ThreatCluster;
import com.sarvatobhadra.backend.threat.ThreatClusterRepository;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.LocalDateTime;
import java.util.List;

/**
 * Service managing Human-in-the-Loop Analyst feedback submission, cluster state updates,
 * and review history tracking.
 */
@Service
@RequiredArgsConstructor
@Slf4j
public class AnalystService {

    private final AnalystRepository analystRepository;
    private final ThreatClusterRepository threatClusterRepository;
    private final BlufRepository blufRepository;

    /**
     * Records analyst review feedback, updates threat cluster status, and synchronizes BLUF review state.
     *
     * @param feedback Analyst feedback record
     * @return Saved {@link AnalystFeedback} entity
     */
    @Transactional
    public AnalystFeedback submitFeedback(AnalystFeedback feedback) {
        log.info("Processing Analyst Feedback for Cluster ID: {}, Action: {}", feedback.getClusterId(), feedback.getAction());

        feedback.setCreatedAt(LocalDateTime.now());
        AnalystFeedback savedFeedback = analystRepository.save(feedback);

        // Update corresponding Threat Cluster status and priority
        ThreatCluster cluster = threatClusterRepository.findById(feedback.getClusterId())
                .orElseThrow(() -> new RuntimeException("Threat Cluster not found with ID: " + feedback.getClusterId()));

        if (feedback.getAction() == FeedbackStatus.CONFIRMED) {
            cluster.setStatus("CONFIRMED");
        } else if (feedback.getAction() == FeedbackStatus.REJECTED) {
            cluster.setStatus("REJECTED");
        } else if (feedback.getAction() == FeedbackStatus.MODIFIED) {
            cluster.setStatus("MODIFIED");
            if (feedback.getModifiedPriority() != null) {
                cluster.setPriority(feedback.getModifiedPriority());
            }
        }
        cluster.setUpdatedAt(LocalDateTime.now());
        threatClusterRepository.save(cluster);

        // Update BLUF Report review status
        blufRepository.findByClusterId(feedback.getClusterId()).ifPresent(bluf -> {
            bluf.setAnalystReviewStatus(feedback.getAction().name());
            if (feedback.getModifiedPriority() != null) {
                bluf.setPriority(feedback.getModifiedPriority());
            }
            blufRepository.save(bluf);
        });

        return savedFeedback;
    }

    public List<AnalystFeedback> getFeedbackByCluster(Long clusterId) {
        return analystRepository.findByClusterId(clusterId);
    }

    public List<AnalystFeedback> getAllFeedback() {
        return analystRepository.findAll();
    }
}
