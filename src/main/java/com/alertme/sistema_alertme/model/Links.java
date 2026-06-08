package com.alertme.sistema_alertme.model;

import jakarta.persistence.*;

@Entity
@Table(name = "links")
public class Links {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(nullable = false, unique = true)
    private String url;

    @Column(nullable = false)
    private boolean isSuspicious;

    @Column(columnDefinition = "TEXT")
    private String reason;

    // Construtor Padrão (Obrigatório para o JPA/Hibernate)
    public Links() {}

    // Construtor Customizado
    public Links(String url, boolean isSuspicious, String reason) {
        this.url = url;
        this.isSuspicious = isSuspicious;
        this.reason = reason;
    }

    // Getters e Setters
    public Long getId() { return id; }
    public void setId(Long id) { this.id = id; }

    public String getUrl() { return url; }
    public void setUrl(String url) { this.url = url; }

    public boolean isSuspicious() { return isSuspicious; }
    public void setSuspicious(boolean suspicious) { this.isSuspicious = suspicious; }

    public String getReason() { return reason; }
    public void setReason(String reason) { this.reason = reason; }
}