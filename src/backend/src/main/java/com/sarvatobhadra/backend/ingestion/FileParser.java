package com.sarvatobhadra.backend.ingestion;

import lombok.extern.slf4j.Slf4j;
import org.apache.tika.Tika;
import org.springframework.stereotype.Component;
import org.springframework.web.multipart.MultipartFile;

import java.io.InputStream;
import java.nio.charset.StandardCharsets;

/**
 * File Parser service using Apache Tika for extracting plain text from multi-format documents
 * (PDF, DOCX, TXT, CSV, JSON).
 */
@Component
@Slf4j
public class FileParser {

    private final Tika tika = new Tika();

    /**
     * Parses content from an uploaded MultipartFile into clean text.
     *
     * @param file Uploaded document or report
     * @return Extracted plain text string
     */
    public String parseFile(MultipartFile file) {
        if (file == null || file.isEmpty()) {
            throw new IllegalArgumentException("File cannot be empty");
        }

        String filename = file.getOriginalFilename();
        log.info("Parsing uploaded file: {}, size: {} bytes", filename, file.getSize());

        try {
            if (filename != null && (filename.endsWith(".txt") || filename.endsWith(".json") || filename.endsWith(".csv"))) {
                return new String(file.getBytes(), StandardCharsets.UTF_8);
            }

            try (InputStream stream = file.getInputStream()) {
                String extractedText = tika.parseToString(stream);
                log.info("Successfully parsed file using Apache Tika. Extracted {} characters.", extractedText.length());
                return extractedText;
            }
        } catch (Exception e) {
            log.error("Error parsing file: {}. Falling back to string representation.", filename, e);
            try {
                return new String(file.getBytes(), StandardCharsets.UTF_8);
            } catch (Exception ex) {
                throw new RuntimeException("Failed to parse file content: " + ex.getMessage(), ex);
            }
        }
    }
}
