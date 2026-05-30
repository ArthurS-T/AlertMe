package com.alertme.sistema_alertme.service;

import com.alertme.sistema_alertme.model.SmsLinks;
import com.alertme.sistema_alertme.repository.SmsRepository;
import org.springframework.stereotype.Service;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.util.List;
import java.util.Optional;

@Service
public class SmsVerificationService {

    private final SmsRepository smsRepository;
    private final VirusTotalService virusTotalService;
    private final LinkVerificationService linkVerificationService;

    // Expressão regular para capturar domínios e URLs dentro do texto
    private static final Pattern URL_PATTERN = Pattern.compile(
            "(https?://(?:www\\.)?[-a-zA-Z0-9@:%._\\+~#=]{1,256}\\.[a-zA-Z0-9()]{2,24}\\b(?:[-a-zA-Z0-9()@:%_\\+.~#?&//=]*))",
            Pattern.CASE_INSENSITIVE);

    public SmsVerificationService(SmsRepository smsRepository, VirusTotalService virusTotalService,
            LinkVerificationService linkVerificationService) {
        this.smsRepository = smsRepository;
        this.virusTotalService = virusTotalService;
        this.linkVerificationService = linkVerificationService;
    }

    // Remoção de protocolo, www e subpastas
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

    public SmsLinks verifySmsText(String smsText) {
        if (smsText == null || smsText.trim().isEmpty()) {
            throw new IllegalArgumentException("O texto do SMS não pode estar vazio.");
        }

        Matcher matcher = URL_PATTERN.matcher(smsText);
        String extractedUrl = null;

        if (matcher.find()) {
            extractedUrl = matcher.group();

            extractedUrl = extractedUrl.replaceAll("[.,]$", "").trim();
            System.out.println("[Debug SMS] URL purificada enviada ao VirusTotal: '" + extractedUrl + "'");
        }

        if (extractedUrl == null) {
            SmsLinks smsSeguro = new SmsLinks(smsText, null, false, "SMS sem nenhum link/URL encontrado.");
            return smsRepository.save(smsSeguro);
        }

        // Tratamento da URL extraida para obter o domínio puro
        String dominioPuro = extrairDominioPuro(extractedUrl);

        try {
            // Consulta a Trie e Banco de Dados local
            boolean isLocalMalicious = linkVerificationService.checkUrlIsMaliciousLocal(dominioPuro);
            if (isLocalMalicious) {
                SmsLinks smsBloqueadoLocal = new SmsLinks(
                        smsText,
                        dominioPuro,
                        true,
                        "Bloqueado: Link contido no SMS pertence a um domínio já marcado como ameaça.");
                return smsRepository.save(smsBloqueadoLocal);
            }

            // Consulta na API VirusTotal
            boolean isMaliciousByVT = virusTotalService.checkUrlIsMalicious(extractedUrl);

            if (isMaliciousByVT) {
                // Sincroniza a Trie local e Banco de links com a nova ameaça descoberta
                linkVerificationService.verifyLink(extractedUrl);

                SmsLinks smsMalicioso = new SmsLinks(
                        smsText,
                        dominioPuro,
                        true,
                        "Bloqueado: Link malicioso detectado dentro do SMS pela API VirusTotal.");
                return smsRepository.save(smsMalicioso);
            }

            SmsLinks smsLinkSeguro = new SmsLinks(
                    smsText,
                    dominioPuro,
                    false,
                    "SMS Verificado: O link contido na mensagem parece seguro.");
            return smsRepository.save(smsLinkSeguro);

        } catch (Exception e) {
            System.err.println("[MSG ERRO] Falha ao processar motores de verificação: " + e.getMessage());

            return new SmsLinks(
                    smsText,
                    dominioPuro,
                    true, // Marcado como true para o frontend tratar como aviso/perigo
                    "Erro: Não foi possível encontrar ou validar a reputação do link contido no SMS devido a uma oscilação na API de segurança.");
        }
    }

    public List<SmsLinks> getAllMessages() {
        return smsRepository.findAll();
    }

    public Optional<SmsLinks> getMessageById(Long id) {
        return smsRepository.findById(id);
    }
}