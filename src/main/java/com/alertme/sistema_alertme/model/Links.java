package com.alertme.sistema_alertme.model;

public class Links {
    private String url;
    private Boolean isSuspicious;
    private String reason;

    public Links(String url, Boolean isSuspicious, String reason) {
        this.url = url;
        this.isSuspicious = isSuspicious;
        this.reason = reason;
    }

    public String getUrl() {
        return url;
    }

    public void setUrl(String url) {
        this.url = url;
    }    

    public Boolean isSuspicious() {
        return isSuspicious;
    }

    public void setSuspicious(Boolean isSuspicious) {
        this.isSuspicious = isSuspicious;
    }

    public String getReason() {
        return reason;
    }

    public void setReason(String reason) {
        this.reason = reason;
    }
    
    public Links() { 
        // Construtor vazio para desserialização
    }
}


