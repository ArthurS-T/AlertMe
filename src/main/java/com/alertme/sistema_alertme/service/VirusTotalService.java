package com.alertme.sistema_alertme.service;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.*;
import org.springframework.stereotype.Service;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;
import org.springframework.web.client.RestTemplate;
import java.util.Map;

@Service
public class VirusTotalService {

    @Value("${virustotal.api.key}")
    private String apiKey;

    @Value("${virustotal.api.url}")
    private String apiUrl;

    private final RestTemplate restTemplate = new RestTemplate();

    public boolean checkUrlIsMalicious(String urlToAnalyze) {
        try {
            // Headers obrigatórios pelo VirusTotal
            HttpHeaders headers = new HttpHeaders();
            headers.set("x-apikey", apiKey);
            headers.setContentType(MediaType.APPLICATION_FORM_URLENCODED);

            MultiValueMap<String, String> map = new LinkedMultiValueMap<>();
            map.add("url", urlToAnalyze);

            HttpEntity<MultiValueMap<String, String>> request = new HttpEntity<>(map, headers);
            // Requisição POST para enviar a URL para análise
            ResponseEntity<Map> response = restTemplate.postForEntity(apiUrl, request, Map.class);

            if (response.getStatusCode() == HttpStatus.OK && response.getBody() != null) {
                Map data = (Map) response.getBody().get("data");
                if (data != null && data.containsKey("id")) {
                    String analysisId = (String) data.get("id");

                    // Aguarda 3 segundos para dar tempo dos motores processarem a URL
                    Thread.sleep(3000);

                    return buscarResultadoAnalise(analysisId);
                }
            }
            return false;
        } catch (Exception e) {
            System.err.println("Erro ao consultar a API do VirusTotal: " + e.getMessage());
            return false;
        }
    }

    private boolean buscarResultadoAnalise(String analysisId) {
        try {
            String urlConsulta = "https://www.virustotal.com/api/v3/analyses/" + analysisId;

            HttpHeaders headers = new HttpHeaders();
            headers.set("x-apikey", apiKey);
            HttpEntity<Void> entity = new HttpEntity<>(headers);

            ResponseEntity<Map> response = restTemplate.exchange(urlConsulta, HttpMethod.GET, entity, Map.class);

            if (response.getStatusCode() == HttpStatus.OK && response.getBody() != null) {
                Map data = (Map) response.getBody().get("data");
                if (data != null && data.containsKey("attributes")) {
                    Map attributes = (Map) data.get("attributes");
                    if (attributes != null && attributes.containsKey("stats")) {
                        Map stats = (Map) attributes.get("stats");

                        // Captura quantos motores detectaram como malicioso ou phishing
                        int malicious = 0;
                        int phishing = 0;
                        int malware = 0;
                        int suspicious = 0;

                        // Pegando todas as métricas críticas de ameaça disponiveis no relatório do VirusTotal
                        if (stats.get("malicious") != null) {
                            malicious = ((Number) stats.get("malicious")).intValue();
                        }
                        if (stats.get("phishing") != null) {
                            phishing = ((Number) stats.get("phishing")).intValue();
                        }
                        if (stats.get("malware") != null) {
                            malware = ((Number) stats.get("malware")).intValue();
                        }
                        if (stats.get("suspicious") != null) {
                            suspicious = ((Number) stats.get("suspicious")).intValue();
                        }

                        // Log completo no console para a resposta do VirusTotal
                        System.out.printf(
                                "[VirusTotal Log] Maliciosos: %d | Phishing: %d | Malware: %d | Suspeitos: %d%n",
                                malicious, phishing, malware, suspicious);

                        int totalDetections = malicious + phishing + malware + suspicious;

                        // Regra de segurança: Se pelo menos 2 motores acusarem ameaça, bloquear.
                        return totalDetections >= 2;
                    }
                }
            }
            return false;
        } catch (Exception e) {
            System.err.println("Erro ao buscar relatório do VirusTotal: " + e.getMessage());
            return false;
        }
    }
}