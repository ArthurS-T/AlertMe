package com.alertme.sistema_alertme.model;

import jakarta.persistence.*;
import java.time.LocalDateTime;

@Entity
@Table(name = "tb_sms_links", indexes = {
@Index(name = "idx_checked_at", columnList = "checkedAt") // Index para que a busca por historico seja mais rápida
})
public class SmsLinks {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(columnDefinition = "TEXT", nullable = false)
    private String smsText;

    private String extractedUrl;
    @com.fasterxml.jackson.annotation.JsonProperty("isSuspicious") // Para garantir que o JSON tenha a propriedade "isSuspicious"
    private boolean isSuspicious;
    private String reason;
    private LocalDateTime checkedAt;

    // Construtores
    public SmsLinks() {}

    public SmsLinks(String smsText, String extractedUrl, boolean isSuspicious, String reason) {
        this.smsText = smsText;
        this.extractedUrl = extractedUrl;
        this.isSuspicious = isSuspicious;
        this.reason = reason;
        this.checkedAt = LocalDateTime.now();
    }

    // Getters e Setters
    public Long getId() { return id; }
    public String getSmsText() { return smsText; }
    public String getExtractedUrl() { return extractedUrl; }
    @com.fasterxml.jackson.annotation.JsonProperty("isSuspicious")
    public boolean isSuspicious() { return isSuspicious; }
    public String getReason() { return reason; }
    public LocalDateTime getCheckedAt() { return checkedAt; }
}