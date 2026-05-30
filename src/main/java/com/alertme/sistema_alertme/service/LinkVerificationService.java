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

    // Método para extrair o domínio puro de uma URL, removendo protocolo, www e
    // subpastas
    private String extrairDominioPuro(String url) {
        if (url == null)
            return "";
        String clean = url.toLowerCase().trim();
        clean = clean.replaceFirst("^(https?://)", "");
        clean = clean.replaceFirst("^(www\\.)", "");
        int slashIndex = clean.indexOf('/');
        if (slashIndex != -1) {
            clean = clean.substring(0, slashIndex);
        }
        return clean;
    }

    public Links verifyLink(String url) {
        if (url == null || url.trim().isEmpty()) {
            return new Links(url, false, "URL inválida ou vazia");
        }

        String dominioPuro = extrairDominioPuro(url);

        // Procura na Trie primeiro
        Trie.SearchResult trieResult = trie.search(dominioPuro);
        if (trieResult.found()) {
            return registrarBanco(dominioPuro, true, "Detectado na lista maliciosa (" + trieResult.source() + ")");
        }

        // Procura no Banco de Dados
        Optional<Links> linkExistente = repository.findByUrl(dominioPuro);
        if (linkExistente.isPresent()) {
            return linkExistente.get();
        }

        // Consulta na API se passou pelos motores
        try {
            boolean isMaliciousVT = virusTotalService.checkUrlIsMalicious(url);

            if (isMaliciousVT) {
                trie.insert(dominioPuro, "VirusTotal");
                return registrarBanco(dominioPuro, true, "Detectado pela API VirusTotal");
            }

            return registrarBanco(dominioPuro, false, "Link seguro");

        } catch (Exception e) {
            System.err.println("[MSG ERRO] Falha ao conectar ao VirusTotal: " + e.getMessage());

            return new Links(
                    url,
                    true, // Alerta o usuário preventivamente
                    "Erro: Não foi possível validar a URL. O motor de análise externa está temporariamente indisponível.");
        }
    }

    private Links registrarBanco(String url, boolean isSuspicious, String reason) {
        try {
            Links record = new Links(url, isSuspicious, reason);
            return repository.save(record);
        } catch (org.springframework.dao.DataIntegrityViolationException e) {
            return repository.findByUrl(url).orElse(new Links(url, isSuspicious, reason));
        }
    }

    public List<Links> getHistory() {
        return repository.findAll();
    }

    public boolean checkUrlIsMaliciousLocal(String url) {
        String dominioPuro = extrairDominioPuro(url);
        Trie.SearchResult trieResult = trie.search(dominioPuro);
        return trieResult.found();
    }
}