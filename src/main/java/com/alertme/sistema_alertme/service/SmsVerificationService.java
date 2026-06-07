package com.alertme.sistema_alertme.service;

import com.alertme.sistema_alertme.model.SmsLinks;
import com.alertme.sistema_alertme.repository.SmsRepository;
import org.springframework.stereotype.Service;

import tools.jackson.databind.ObjectMapper;

import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.util.List;
import java.util.Map;
import java.util.Optional;

@Service
public class SmsVerificationService {

    private final SmsRepository smsRepository;
    private final VirusTotalService virusTotalService;
    private final LinkVerificationService linkVerificationService;
    private final GeminiService geminiService; // Injeção do Gemini
    private final ObjectMapper objectMapper = new ObjectMapper();

    // Expressão regular para capturar domínios e URLs dentro dos textos
    private static final Pattern URL_PATTERN = Pattern.compile(
            "(https?://(?:www\\.)?[-a-zA-Z0-9@:%._\\+~#=]{1,256}\\.[a-zA-Z0-9()]{2,24}\\b(?:[-a-zA-Z0-9()@:%_\\+.~#?&//=]*))",
            Pattern.CASE_INSENSITIVE);

    public SmsVerificationService(SmsRepository smsRepository, VirusTotalService virusTotalService,
                                  LinkVerificationService linkVerificationService, GeminiService geminiService) {
        this.smsRepository = smsRepository;
        this.virusTotalService = virusTotalService;
        this.linkVerificationService = linkVerificationService;
        this.geminiService = geminiService;
    }

    // Remove de protocolo, www e subpastas
    private String extrairDominioPuro(String url) {
        if (url == null) return "";
        String clean = url.toLowerCase().trim();
        clean = clean.replaceFirst("^(https?://)", "");
        clean = clean.replaceFirst("^(www\\.)", "");
        int slashIndex = clean.indexOf('/');
        if (slashIndex != -1) {
            clean = clean.substring(0, slashIndex);
        }
        return clean;
    }

    public SmsLinks verifySmsText(String smsText) {
        if (smsText == null || smsText.trim().isEmpty()) {
            throw new IllegalArgumentException("O texto do SMS não pode estar vazio.");
        }

        Matcher matcher = URL_PATTERN.matcher(smsText);
        String extractedUrl = null;

        if (matcher.find()) {
            extractedUrl = matcher.group().replaceAll("[.,]$", "").trim();
        }

        // Se o SMS não tem link, passamos pelo Gemini para avaliar se é um golpe de engenharia social por texto puro
        if (extractedUrl == null) {
            String jsonIA = geminiService.analisarTexto(smsText);
            String motivoIA = extrairMotivoDaIA(jsonIA, "SMS sem nenhum link/URL encontrado.");
            boolean suspeitoIA = extrairStatusDaIA(jsonIA, false);
            
            return smsRepository.save(new SmsLinks(smsText, null, suspeitoIA, motivoIA));
        }

        String dominioPuro = extrairDominioPuro(extractedUrl);

        try {
            // Consulta Local
            boolean isLocalMalicious = linkVerificationService.checkUrlIsMaliciousLocal(dominioPuro);
            if (isLocalMalicious) {
                String jsonIA = geminiService.analisarTexto(smsText);
                String motivoIA = extrairMotivoDaIA(jsonIA, "Bloqueado: Link contido no SMS pertence a um domínio marcado como ameaça.");
                return smsRepository.save(new SmsLinks(smsText, dominioPuro, true, motivoIA));
            }

            // Consulta Externa VirusTotal
            VirusTotalService.VTResult vtResult = virusTotalService.checkUrlIsMalicious(extractedUrl);

            if (vtResult.isMalicious()) {
                linkVerificationService.verifyLink(extractedUrl); // Sincroniza localmente
                
                String jsonIA = geminiService.analisarTexto(smsText);
                String motivoIA = extrairMotivoDaIA(jsonIA, "Bloqueado: Link malicioso detectado dentro do SMS.");
                return smsRepository.save(new SmsLinks(smsText, dominioPuro, true, motivoIA));
            }

            //  Validando o contexto do texto com a IA
            String jsonIA = geminiService.analisarTexto(smsText);
            boolean suspeitoPorContexto = extrairStatusDaIA(jsonIA, false);
            String motivoIA = extrairMotivoDaIA(jsonIA, "SMS verificado com sucesso.");

            return smsRepository.save(new SmsLinks(smsText, dominioPuro, suspeitoPorContexto, motivoIA));

        } catch (Exception e) {
            System.err.println("[MSG ERRO] Falha ao processar motores: " + e.getMessage());
            return new SmsLinks(smsText, dominioPuro, true, "Erro ao validar a reputação do link contido no SMS.");
        }
    }

    private String extrairMotivoDaIA(String jsonIA, String fallback) {
        try {
            Map<String, Object> mapa = objectMapper.readValue(jsonIA, Map.class);
            if (mapa != null && mapa.containsKey("reason")) return (String) mapa.get("reason");
        } catch (Exception e) {}
        return fallback;
    }

    private boolean extrairStatusDaIA(String jsonIA, boolean fallback) {
        try {
            Map<String, Object> mapa = objectMapper.readValue(jsonIA, Map.class);
            if (mapa != null && mapa.containsKey("isSuspicious")) return (boolean) mapa.get("isSuspicious");
        } catch (Exception e) {}
        return fallback;
    }

    public List<SmsLinks> getAllMessages() { return smsRepository.findAll(); }
}