package com.alertme.sistema_alertme.model;

import jakarta.persistence.*;
import java.time.LocalDateTime;

@Entity
@Table(name = "tb_sms_links", indexes = {
    @Index(name = "idx_checked_at", columnList = "checkedAt")
})
public class SmsLinks {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(columnDefinition = "TEXT", nullable = false)
    private String smsText;

    @Column(columnDefinition = "TEXT") // Permite URLs muito longas (com tokens ou parâmetros extensos)
    private String extractedUrl;

    @com.fasterxml.jackson.annotation.JsonProperty("isSuspicious")
    private boolean isSuspicious;

    @Column(columnDefinition = "TEXT") // Permite relatórios detalhados pela IA do Gemini sem estourar o limite do banco
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