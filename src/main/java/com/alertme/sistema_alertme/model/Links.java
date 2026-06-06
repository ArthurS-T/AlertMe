package com.alertme.sistema_alertme.model;

import jakarta.persistence.*;
import com.fasterxml.jackson.annotation.JsonProperty;

@Entity
@Table(name = "tb_links", uniqueConstraints = {@UniqueConstraint(columnNames = {"url"})})
public class Links {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY) // ID autoincrementável
    private Long id;

    @Column(nullable = false, length = 500)
    private String url;

    @JsonProperty("isSuspicious")
    @Column(nullable = false)
    private boolean isSuspicious;

    @Column(columnDefinition = "TEXT")
    private String reason;

    // Construtores
    public Links() {}

    public Links(String url, boolean isSuspicious, String reason) {
        this.url = url;
        this.isSuspicious = isSuspicious;
        this.reason = reason;
    }

    // Getters e Setters
    public Long getId() { return id; }
    
    public String getUrl() { return url; }
    public void setUrl(String url) { this.url = url; }

    public boolean isSuspicious() { return isSuspicious; }
    public void setSuspicious(boolean isSuspicious) { this.isSuspicious = isSuspicious; }

    public String getReason() { return reason; }
    public void setReason(String reason) { this.reason = reason; }
}