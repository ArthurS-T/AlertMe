package com.alertme.sistema_alertme.service;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;
import org.springframework.web.client.RestTemplate;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

@Service
public class GeminiService {

    @Value("${gemini.api.key}")
    private String apiKey;

    private final RestTemplate restTemplate = new RestTemplate();
    // URL base da API Gemini
    private final String API_URL = "https://generativelanguage.googleapis.com/v1beta/models/gemini-1.5-flash:generateContent?key=";

    // Analisa o contexto de mensagens de texto (SMS)
    public String analisarTexto(String texto) {
        String url = API_URL + apiKey;

        String prompt = "Você é um especialista em segurança digital do sistema AlertMe. "
                + "Analise o seguinte texto e identifique indícios de Engenharia Social ou 'Golpe do Presente'. "
                + "Responda estritamente em JSON com as chaves: 'isSuspicious' (boolean) e 'reason' (string didática em português). "
                + "Retorne apenas o JSON puro, sem markdown. "
                + "Texto: " + texto;

        try {
            return enviarRequisicao(url, prompt);
        } catch (Exception e) {
            return "{\"isSuspicious\": false, \"reason\": \"Análise textual indisponível no momento.\"}";
        }
    }

    // Explica o perigo de uma URL com base nos dados do VirusTotal
    public String explicarUrl(String urlAlvo, int maliciosos, int suspeitos) {
        String url = API_URL + apiKey;
        String prompt;

        if (maliciosos == 0 && suspeitos == 0) {
            prompt = "Você é um especialista em segurança digital do sistema AlertMe. "
                    + "A URL [" + urlAlvo+ "] passou limpa pelas verificações globais do VirusTotal (0 ameaças encontradas). "
                    + "Gere um JSON com: 'isSuspicious' (boolean, que deve ser false) e 'reason' (uma explicação curta, amigável e didática em português para leigos sobre por que este link parece seguro para navegar). "
                    + "Retorne apenas o JSON puro, sem markdown.";
        } else {
            prompt = "Você é um especialista em segurança digital do sistema AlertMe. "
                    + "A URL [" + urlAlvo + "] foi marcada por " + maliciosos + " motores como maliciosa e " + suspeitos+ " como suspeita no VirusTotal. "
                    + "Gere um JSON com: 'isSuspicious' (boolean, que deve ser true) e 'reason' (explicação curta e didática em português sobre o risco de roubo de dados para leigos). "
                    + "Retorne apenas o JSON puro, sem markdown.";
        }

        try {
            return enviarRequisicao(url, prompt);
        } catch (Exception e) {
            boolean perigo = (maliciosos > 0 || suspeitos > 0);
            return "{\"isSuspicious\": " + perigo
                    + ", \"reason\": \"Link analisado pelos motores globais de segurança.\"}";
        }
    }

    // Método central de comunicação com a API

    private String enviarRequisicao(String url, String prompt) throws Exception {
        HttpHeaders headers = new HttpHeaders();
        headers.setContentType(MediaType.APPLICATION_JSON);

        Map<String, Object> textPart = new HashMap<>();
        textPart.put("text", prompt);

        Map<String, Object> contents = new HashMap<>();
        contents.put("contents", List.of(Map.of("parts", List.of(textPart))));

        HttpEntity<Map<String, Object>> entity = new HttpEntity<>(contents, headers);
        Map<String, Object> response = restTemplate.postForObject(url, entity, Map.class);

        // Extração simplificada do texto da resposta
        List<Map<String, Object>> candidates = (List<Map<String, Object>>) response.get("candidates");
        Map<String, Object> content = (Map<String, Object>) candidates.get(0).get("content");
        List<Map<String, Object>> parts = (List<Map<String, Object>>) content.get("parts");

        return (String) parts.get(0).get("text");
    }
}