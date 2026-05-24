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
            HttpHeaders headers = new HttpHeaders();
            headers.set("x-apikey", apiKey);
            headers.setContentType(MediaType.APPLICATION_FORM_URLENCODED);

            MultiValueMap<String, String> map = new LinkedMultiValueMap<>();
            map.add("url", urlToAnalyze);

            HttpEntity<MultiValueMap<String, String>> request = new HttpEntity<>(map, headers);
            ResponseEntity<Map> response = restTemplate.postForEntity(apiUrl, request, Map.class);

            if (response.getStatusCode() == HttpStatus.OK && response.getBody() != null) {
                Map data = (Map) response.getBody().get("data");
                if (data != null && data.containsKey("id")) {
                    String analysisId = (String) data.get("id");

                    return buscarResultadoAnalise(analysisId);
                }
            }
            return false;
        } catch (Exception e) {
            System.err.println("Erro ao consultar a API do VirusTotal: " + e.getMessage());
            return false;
        }
    }

    // Loop para que o serviço aguarde a análise ser concluída, verificando a cada 5 segundos, por até 30 segundos
    private boolean buscarResultadoAnalise(String analysisId) {
        String urlConsulta = "https://www.virustotal.com/api/v3/analyses/" + analysisId;
        HttpHeaders headers = new HttpHeaders();
        headers.set("x-apikey", apiKey);
        HttpEntity<Void> entity = new HttpEntity<>(headers);

        // Tenta 6 vezes
        for (int i = 0; i < 6; i++) {
            try {
                Thread.sleep(5000);
                ResponseEntity<Map> response = restTemplate.exchange(urlConsulta, HttpMethod.GET, entity, Map.class);

                if (response.getStatusCode() == HttpStatus.OK && response.getBody() != null) {
                    Map data = (Map) response.getBody().get("data");
                    if (data != null && data.containsKey("attributes")) {
                        Map attributes = (Map) data.get("attributes");

                        String status = (String) attributes.get("status");
                        // Se o VirusTotal ainda estiver processando em fila, repete o loop
                        if (!"completed".equalsIgnoreCase(status)) {
                            System.out.println("[VirusTotal] Link em fila de análise... Tentativa " + (i + 1));
                            continue;
                        }

                        if (attributes.containsKey("stats")) {
                            Map stats = (Map) attributes.get("stats");

                            int malicious = stats.get("malicious") != null
                                    ? ((Number) stats.get("malicious")).intValue()
                                    : 0;
                            int phishing = stats.get("phishing") != null ? ((Number) stats.get("phishing")).intValue()
                                    : 0;
                            int malware = stats.get("malware") != null ? ((Number) stats.get("malware")).intValue() : 0;
                            int suspicious = stats.get("suspicious") != null
                                    ? ((Number) stats.get("suspicious")).intValue()
                                    : 0;

                            System.out.printf(
                                    "[VirusTotal Log] Concluído! Maliciosos: %d | Phishing: %d | Malware: %d | Suspeitos: %d%n",
                                    malicious, phishing, malware, suspicious);

                            return (malicious + phishing + malware + suspicious) >= 2;
                        }
                    }
                }
            } catch (Exception e) {
                System.err.println("Erro na amostragem da análise: " + e.getMessage());
            }
        }
        return false;
    }
}