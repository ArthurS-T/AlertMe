package com.alertme.sistema_alertme.service;

import com.alertme.sistema_alertme.model.Links;
import com.alertme.sistema_alertme.service.engine.Trie;
import java.util.ArrayList;
import java.util.List;

import org.springframework.stereotype.Service;

@Service
public class LinkVerificationService {

    private final Trie trie = new Trie();
    private final List<Links> history = new ArrayList<>();

    public LinkVerificationService() {
        // Exemplo de inserção de domínios maliciosos
        trie.insert("malware.com", "STATIC");
        trie.insert("phishing.com", "STATIC");
    }

    public Links verifyLink(String url) {
        Trie.SearchResult trieResult = trie.search(url);

        if (trieResult.found()) {
            return registrarBanco(url, true, "Detectado na lista maliciosa (" + trieResult.source() + ")");
        }
        // Verificação adicional com IA (simulada)
        if (simularIA(url)) {
            trie.insert(url, "IA");
            return registrarBanco(url, true, "Detectado por IA");
    }
        return registrarBanco(url, false, "Link seguro");
    }
    
    private Links registrarBanco(String url, boolean isSuspicious, String reason) {
        Links record = new Links(url, isSuspicious, reason);
        history.add(record);
        return record;
    }

    private boolean simularIA(String url){
        return url.contains("suspicious");
    }

    public List<Links> getHistory() {
        return new ArrayList<>(history);
    }

}






