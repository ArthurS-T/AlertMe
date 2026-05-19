package com.alertme.sistema_alertme.service.engine;

import java.util.HashMap;
import java.util.Map;

public class Trie {

    // O nó da arvore Trie
   private static class TrieNode {
        private final Map<Character, TrieNode> children = new HashMap<>();
        private boolean isEndOfDomain = false;
        private String source = "STATIC"; // Identifica se foi inserido por IA ou Base Fixa

        public void setEndOfDomain(boolean endOfDomain, String source) {
            this.isEndOfDomain = endOfDomain;
            this.source = source;
        }
    }

    private final TrieNode root;

    public Trie() {
        this.root = new TrieNode();
    }

    // Método para normalizar URLs (remover protocolo, www, etc.)
    private String normalize(String url) {
        if (url == null) return "";
        
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
        if (normalized.isEmpty()) return; // Evita inserir domínios vazios

        TrieNode current = root;
        for (char ch : normalized.toCharArray()) {
            current = current.children.computeIfAbsent(ch, k -> new TrieNode());
        }
        current.setEndOfDomain(true, source);
    }

    // Método de busca
    public SearchResult search(String url) {
        String normalized = normalize(url);
        if (normalized.isEmpty()) return new SearchResult(false, null); // Evita buscas vazias

        TrieNode current = root;
        for (char ch : normalized.toCharArray()) {
            current = current.children.get(ch);
            if (current == null) {
                return new SearchResult(false, null);
            }
            if (current.isEndOfDomain) {
                return new SearchResult(true, current.source);
            }
        }
        return new SearchResult(false, null);
    }

    // Classe auxiliar para o retorno da busca
    public record SearchResult(boolean found, String source) {}
}

