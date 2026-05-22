package com.alertme.sistema_alertme.service;

import com.alertme.sistema_alertme.model.Links;
import com.alertme.sistema_alertme.repository.LinkRepository;
import com.alertme.sistema_alertme.service.engine.Trie;
import org.springframework.stereotype.Service;
import java.util.List;

@Service
public class LinkVerificationService {

    private final Trie trie = new Trie();
    private final LinkRepository repository; // Injeção do Repository
    private final VirusTotalService virusTotalService; // Integrando o serviço do VirusTotal

    // O Spring injeta o repository automaticamente aqui
    public LinkVerificationService(LinkRepository repository, VirusTotalService virusTotalService) {
        this.repository = repository;
        this.virusTotalService = virusTotalService; 
        
        // Teste inicial estático na Trie
        trie.insert("malware.com", "STATIC");
        trie.insert("phishing.com", "STATIC");
    }

    public Links verifyLink(String url) {
        Trie.SearchResult trieResult = trie.search(url);

        if (trieResult.found()) {
            return registrarBanco(url, true, "Detectado na lista maliciosa (" + trieResult.source() + ")");
        }

        boolean isMaliciousVT = virusTotalService.checkUrlIsMalicious(url);
        
        if (isMaliciousVT) {
            trie.insert(url, "VirusTotal"); 
            return registrarBanco(url, true, "Detectado pela API VirusTotal");
        }
        
        return registrarBanco(url, false, "Link seguro");
    }
    
    private Links registrarBanco(String url, boolean isSuspicious, String reason) {
        Links record = new Links(url, isSuspicious, reason);
        return repository.save(record); // Salva diretamente no PostgreSQL!
    }


    public List<Links> getHistory() {
        return repository.findAll(); // Busca todos os registros do PostgreSQL!
    }
}