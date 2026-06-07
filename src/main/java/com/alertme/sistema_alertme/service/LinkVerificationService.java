package com.alertme.sistema_alertme.service;

import com.alertme.sistema_alertme.model.Links;
import com.alertme.sistema_alertme.repository.LinkRepository;
import com.alertme.sistema_alertme.service.arvore.Trie;

import tools.jackson.databind.ObjectMapper;

import org.springframework.stereotype.Service;
import java.util.List;
import java.util.Map;
import java.util.Optional;

@Service
public class LinkVerificationService {

    private final Trie trie = new Trie();
    private final LinkRepository repository; // Injeção do Repository
    private final VirusTotalService virusTotalService; // Integrando o serviço do VirusTotal
    private final GeminiService geminiService; // Injeção do Gemini
    private final ObjectMapper objectMapper = new ObjectMapper(); // Para ler o JSON da IA

    public LinkVerificationService(LinkRepository repository, VirusTotalService virusTotalService,
            GeminiService geminiService) {
        this.repository = repository;
        this.virusTotalService = virusTotalService;
        this.geminiService = geminiService;

        trie.insert("malware.com", "STATIC");
        trie.insert("phishing.com", "STATIC");
    }

    // Método para extrair o domínio puro de uma URL, removendo protocolo, www e subpastas
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
            String explicacaoIA = extrairMotivoDaIA(geminiService.explicarUrl(dominioPuro, 5, 0),
                    "Detectado na lista maliciosa local.");
            return registrarBanco(dominioPuro, true, explicacaoIA);
        }

        // Procura no Banco de Dados
        Optional<Links> linkExistente = repository.findByUrl(dominioPuro);
        if (linkExistente.isPresent()) {
            return linkExistente.get();
        }

        // Consulta na API VirusTotal + IA Gemini
        try {
            VirusTotalService.VTResult vtResult = virusTotalService.checkUrlIsMalicious(url);

            // Passa os dados VirusTotal pro Gemini
            String jsonBrutoDaIA = geminiService.explicarUrl(dominioPuro, vtResult.maliciousCount(),
                    vtResult.suspiciousCount());

            // Extrai o motivo didático
            String motivoExplicadoPelaIA = extrairMotivoDaIA(jsonBrutoDaIA,
                    vtResult.isMalicious() ? "Detectado pela API VirusTotal" : "Link seguro");

            // Extrai o veredito final combinando VirusTotal e IA
            boolean vereditoFinalSuspeito = vtResult.isMalicious() || extrairStatusDaIA(jsonBrutoDaIA, false);

            if (vereditoFinalSuspeito) {
                // Se o VirusTotal confirmou a ameaça, alimenta a árvore Trie
                if (vtResult.isMalicious()) {
                    trie.insert(dominioPuro, "VirusTotal");
                }
                return registrarBanco(dominioPuro, true, motivoExplicadoPelaIA);
            }

            return registrarBanco(dominioPuro, false, motivoExplicadoPelaIA);

        } catch (Exception e) {
            System.err.println("[MSG ERRO] Falha ao conectar aos serviços externos: " + e.getMessage());
            return new Links(url, true, "Erro: Não foi possível validar a URL na nuvem de segurança.");
        }
    }

    // Método para ler a string JSON gerada pela IA e isolar apenas 'reason'

    private String extrairMotivoDaIA(String jsonIA, String fallback) {
        try {
            Map<String, Object> mapa = objectMapper.readValue(jsonIA, Map.class);
            if (mapa != null && mapa.containsKey("reason")) {
                return (String) mapa.get("reason");
            }
        } catch (Exception e) {
            System.err.println("Erro ao fazer o parse do JSON da IA: " + e.getMessage());
        }
        return fallback;
    }

    private boolean extrairStatusDaIA(String jsonIA, boolean fallback) {
        try {
            Map<String, Object> mapa = objectMapper.readValue(jsonIA, Map.class);
            if (mapa != null && mapa.containsKey("isSuspicious"))
                return (boolean) mapa.get("isSuspicious");
        } catch (Exception e) {
        }
        return fallback;
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