package com.alertme.sistema_alertme.service.arvore;

import java.util.concurrent.ConcurrentHashMap;
import java.util.Map;

public class Trie {

    // O nó da arvore Trie
    private static class TrieNode {
        private final Map<Character, TrieNode> children = new ConcurrentHashMap<>();
        private boolean isEndOfDomain = false;
        private String source = "STATIC"; // Identifica se foi inserido pelo VirusTotal ou Estático para testes
        private java.time.LocalDateTime createdAt = java.time.LocalDateTime.now();

        public void setEndOfDomain(boolean endOfDomain, String source) {
            this.isEndOfDomain = endOfDomain;
            this.source = source;
            this.createdAt = java.time.LocalDateTime.now();
        }
    }

    private final TrieNode root;

    public Trie() {
        this.root = new TrieNode();
    }

    // Método para normalizar URLs (remover protocolo, www, etc.)
    private String normalize(String url) {
        if (url == null)
            return "";

        String cleanUrl = url.toLowerCase().trim();

        // 1. Remover protocolo (http:// ou https://)
        cleanUrl = cleanUrl.replaceFirst("^(https?://)", "");

        // 2. Remover www.
        cleanUrl = cleanUrl.replaceFirst("^(www\\.)", "");

        // 3. Remover subpastas e parâmetros (focar no domínio), se houver uma barra "/", pega apenas o que vem antes dela
        int slashIndex = cleanUrl.indexOf('/');
        if (slashIndex != -1) {
            cleanUrl = cleanUrl.substring(0, slashIndex);
        }

        return cleanUrl;
    }

    // Método para inserir domínios maliciosos
    public void insert(String domain, String source) {
        String normalized = normalize(domain);
        if (normalized.isEmpty())
            return; // Evita inserir domínios vazios

        TrieNode current = root;
        for (char ch : normalized.toCharArray()) {
            current = current.children.computeIfAbsent(ch, k -> new TrieNode());
        }
        current.setEndOfDomain(true, source);
    }

    // Método de busca na arvore
    public SearchResult search(String url) {
        String normalized = normalize(url);
        if (normalized.isEmpty())
            return new SearchResult(false, null);

        // 1. Busca o domínio exato como foi enviado
        SearchResult result = searchExact(normalized);
        if (result.found()) {
            return result;
        }

        // 2. Se não achou, quebra o domínio para caçar domínios pais/raiz bloqueados
        String[] parts = normalized.split("\\.");
        if (parts.length > 2) {
            StringBuilder currentDomain = new StringBuilder();

            for (int i = parts.length - 2; i >= 0; i--) {
                currentDomain.insert(0, parts[i] + (currentDomain.length() > 0 ? "." + parts[parts.length - 1] : ""));

                // Para garantir que subdominios de sites já bloqueado seja bloqueado automaticamente, sem precisar de uma nova consulta na API.
                SearchResult subResult = searchExact(currentDomain.toString());
                if (subResult.found()) {
                    return new SearchResult(true, subResult.source() + " (Bloqueado via Domínio Raiz)");
                }
            }
        }

        return new SearchResult(false, null);
    }

    // Método auxiliar
    private SearchResult searchExact(String normalizedDomain) {
        TrieNode current = root;
        for (char ch : normalizedDomain.toCharArray()) {
            current = current.children.get(ch);
            if (current == null) {
                return new SearchResult(false, null);
            }

            if (current.isEndOfDomain) {
                // Se foi inserido pela API do VirusTotal e passou de 24 horas, expira
                if ("VirusTotal".equalsIgnoreCase(current.source) &&
                        current.createdAt.isBefore(java.time.LocalDateTime.now().minusHours(24))) {

                    current.isEndOfDomain = false; // Reseta o nó na memória
                    System.out.println("[Trie Cache] Link expirou da memória RAM após 24h: " + normalizedDomain);
                    return new SearchResult(false, null);
                }
                return new SearchResult(true, current.source);
            }
        }
        return new SearchResult(false, null);
    }

    // Classe auxiliar para o retorno da busca
    public record SearchResult(boolean found, String source) {
    }
}
