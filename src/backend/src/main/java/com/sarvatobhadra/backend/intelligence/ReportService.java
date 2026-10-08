package com.sarvatobhadra.backend.intelligence;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.List;

/**
 * Service managing Intelligence Report storage, queries, and cluster linking.
 */
@Service
@RequiredArgsConstructor
@Slf4j
public class ReportService {

    private final ReportRepository reportRepository;

    public List<IntelligenceReport> getAllReports() {
        return reportRepository.findAll();
    }

    public IntelligenceReport getReportById(Long id) {
        return reportRepository.findById(id)
                .orElseThrow(() -> new RuntimeException("Intelligence Report not found with ID: " + id));
    }

    public List<IntelligenceReport> getReportsByCluster(Long clusterId) {
        return reportRepository.findByClusterId(clusterId);
    }

    @Transactional
    public IntelligenceReport saveReport(IntelligenceReport report) {
        log.info("Saving Intelligence Report: {}", report.getTitle());
        return reportRepository.save(report);
    }
}
