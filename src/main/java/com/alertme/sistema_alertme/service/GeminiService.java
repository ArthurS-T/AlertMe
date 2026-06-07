package com.alertme.sistema_alertme.service;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;
import org.springframework.web.client.RestTemplate;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.client.HttpClientErrorException;

import java.util.Map;

@Service
public class GeminiService {

    @Value("${gemini.api.key}")
    private String apiKey;

    private final RestTemplate restTemplate = new RestTemplate();
    
    private final tools.jackson.databind.ObjectMapper objectMapper = new tools.jackson.databind.ObjectMapper();

    // URL da API do Gemini Flash
    private final String API_URL = "https://generativelanguage.googleapis.com/v1beta/models/gemini-flash-latest:generateContent";

    // Analisa o contexto de mensagens de texto (SMS)
    public String analisarTexto(String texto) {
        if (apiKey == null || apiKey.trim().isEmpty() || apiKey.equals("${GEMINI_API_KEY}")) {
            System.err.println("[Gemini DEBUG] A chave API_KEY está nula ou ausente!");
            return "{\"isSuspicious\": false, \"reason\": \"Análise textual indisponível (Chave de API ausente).\"}";
        }

        String prompt = "Você é um especialista em segurança digital do sistema AlertMe. "
                + "Analise o seguinte texto e identifique indícios de Engenharia Social ou 'Golpe do Presente'. "
                + "Responda estritamente em JSON com as chaves: 'isSuspicious' (boolean) e 'reason' (string didática em português). "
                + "Retorne apenas o JSON puro, sem markdown. " + "Texto: " + texto;

        try {
            return enviarRequisicao(prompt);
        } catch (Exception e) {
            System.err.println("[Gemini DEBUG] Erro ao analisar texto: " + e.getMessage());
            return "{\"isSuspicious\": false, \"reason\": \"Análise textual indisponível no momento.\"}";
        }
    }

    // Explica o perigo de uma URL com base nos dados do VirusTotal
    public String explicarUrl(String urlAlvo, int maliciosos, int suspeitos) {
        if (apiKey == null || apiKey.trim().isEmpty() || apiKey.equals("${GEMINI_API_KEY}")) {
            System.err.println("[Gemini DEBUG] A chave API_KEY está nula ou ausente!");
            boolean perigo = (maliciosos > 0 || suspeitos > 0);
            return "{\"isSuspicious\": " + perigo + ", \"reason\": \"Link analisado pelos motores locais (IA indisponível).\"}";
        }

        String prompt;
        if (maliciosos == 0 && suspeitos == 0) {
            prompt = "Você é um especialista em segurança digital do sistema AlertMe. "
                    + "A URL [" + urlAlvo + "] passou limpa pelas verificações globais do VirusTotal (0 ameaças encontradas). "
                    + "Gere um JSON com as chaves exatas: 'isSuspicious' (boolean, que deve ser false) e 'reason' (uma explicação curta, rica e didática em português para todos sobre por que este link específico parece seguro e quais indícios mostram que ele é confiável). "
                    + "Retorne apenas o JSON puro, sem markdown.";
        } else {
            prompt = "Você é um especialista em segurança digital do sistema AlertMe. "
                    + "A URL [" + urlAlvo + "] foi marcada por " + maliciosos + " motores como maliciosa e " + suspeitos + " como suspeita no VirusTotal. "
                    + "Gere um JSON com as chaves exatas: 'isSuspicious' (boolean, que deve ser true) e 'reason' (uma explicação curta, rica e visualmente didática em português detalhando quais indícios provam que este link é uma ameaça de engenharia social, roubo de dados ou clonagem). "
                    + "Retorne apenas o JSON puro, sem markdown.";
        }

        try {
            return enviarRequisicao(prompt);
        } catch (Exception e) {
            System.err.println("[Gemini DEBUG] Erro crítico na chamada da API: " + e.getMessage());
            
            // Garantir que mesmo em caso de falha da IA, o sistema retorna uma resposta coerente baseada nos dados disponíveis do VirusTotal
            boolean perigoReal = (maliciosos > 0 || suspeitos > 0);
            String mensagemFallback = perigoReal 
                ? "Atenção: Este link foi bloqueado porque apresenta sérios indícios de engenharia social, clonagem de páginas ou roubo de credenciais." 
                : "Este link parece seguro para navegação. Não encontramos registros de fraudes ou ameaças ativas associadas a ele.";

            return "{\"isSuspicious\": " + perigoReal + ", \"reason\": \"" + mensagemFallback + "\"}";
        }
    }

    // Método centralizado que agora envia a chave através de Headers HTTP
    private String enviarRequisicao(String prompt) throws Exception {
        HttpHeaders headers = new HttpHeaders();
        headers.setContentType(MediaType.APPLICATION_JSON);
        
        String chaveLimpa = apiKey.replaceAll("\\s+", "").trim();
        headers.set("X-goog-api-key", chaveLimpa);

        String promptSanitizado = prompt.replace("\\", "\\\\")
                                        .replace("\"", "\\\"")
                                        .replace("\n", "\\n")
                                        .replace("\r", "\\r");

        String jsonCorpo = "{\n" +
                "  \"contents\": [\n" +
                "    {\n" +
                "      \"parts\": [\n" +
                "        {\n" +
                "          \"text\": \"" + promptSanitizado + "\"\n" +
                "        }\n" +
                "      ]\n" +
                "    }\n" +
                "  ]\n" +
                "}";

        HttpEntity<String> entity = new HttpEntity<>(jsonCorpo, headers);

        try {
            ResponseEntity<Map> responseEntity = restTemplate.exchange(API_URL, org.springframework.http.HttpMethod.POST, entity, Map.class);
            Map<String, Object> response = responseEntity.getBody();

            if (response == null || !response.containsKey("candidates")) {
                throw new RuntimeException("Resposta vazia obtida dos servidores do Gemini.");
            }

            tools.jackson.databind.JsonNode rootNode = objectMapper.valueToTree(response);
            String textoPuro = rootNode.path("candidates").path(0).path("content").path("parts").path(0).path("text").asText();
          
            // Limpando formatação pra garantir o JSON puro
            if (textoPuro.contains("```")) {
                textoPuro = textoPuro.replaceAll("```json", "").replaceAll("```", "").trim();
            }

            return textoPuro;

        } catch (HttpClientErrorException e) {
            // Print no log do Render
            System.err.println("[Gemini Http Error Body]: " + e.getResponseBodyAsString());
            throw e;
        }
    }
}