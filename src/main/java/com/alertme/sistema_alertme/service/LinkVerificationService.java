package com.alertme.sistema_alertme.service;

import com.alertme.sistema_alertme.model.Links;
import com.alertme.sistema_alertme.repository.LinkRepository;
import com.alertme.sistema_alertme.service.arvore.Trie;
import org.springframework.stereotype.Service;
import java.util.List;
import java.util.Optional;

@Service
public class LinkVerificationService {

    private final Trie trie = new Trie();
    private final LinkRepository repository; // Injeção do Repository
    private final VirusTotalService virusTotalService; // Integrando o serviço do VirusTotal

    public LinkVerificationService(LinkRepository repository, VirusTotalService virusTotalService) {
        this.repository = repository;
        this.virusTotalService = virusTotalService;

        // Teste inicial estático na Trie
        trie.insert("malware.com", "STATIC");
        trie.insert("phishing.com", "STATIC");
    }

    public Links verifyLink(String url) {
        if (url == null || url.trim().isEmpty()){
            return new Links(url, false, "URL inválida ou vazia");
        }

        // Verifica se o link já existe no Banco de Dados
        Optional<Links> linkExistente = repository.findByUrl(url);
        if (linkExistente.isPresent()) {
            return linkExistente.get();
        }

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
        try{
        Links record = new Links(url, isSuspicious, reason);
        return repository.save(record); // Salva diretamente no PostgreSQL
        } catch (org.springframework.dao.DataIntegrityViolationException e) {
            // Se outra thread salvou o mesmo link frações de segundo antes, busca o registro existente
            return repository.findByUrl(url).orElse(new Links(url, isSuspicious, reason));
        }
    }

    public List<Links> getHistory() {
        return repository.findAll(); // Busca todos os registros do PostgreSQL
    }

    // Consulta se o link já foi banido e está guardado na memória da árvore Trie
    public boolean checkUrlIsMaliciousLocal(String url) {
        Trie.SearchResult trieResult = trie.search(url);
        return trieResult.found();
    }
}