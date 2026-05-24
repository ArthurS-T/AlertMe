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
    private static final String URL_REGEX = "https?://[a-zA-Z0-9.-]+\\.[a-zA-Z]{2,6}(/[a-zA-Z0-9._%+-]*)*";
    private static final Pattern pattern = Pattern.compile(URL_REGEX, Pattern.CASE_INSENSITIVE);

    public SmsVerificationService(SmsRepository smsRepository, VirusTotalService virusTotalService, LinkVerificationService linkVerificationService) {
        this.smsRepository = smsRepository;
        this.virusTotalService = virusTotalService;
        this.linkVerificationService = linkVerificationService;
    }

    public SmsLinks verifySmsText(String smsText) {
        if (smsText == null || smsText.trim().isEmpty()) {
            throw new IllegalArgumentException("O texto do SMS não pode estar vazio.");
        }

        Matcher matcher = pattern.matcher(smsText);
        String extractedUrl = null;

        if (matcher.find()) {
            extractedUrl = matcher.group();

            extractedUrl = extractedUrl.replaceAll("[.,]$", "").trim();
            System.out.println("[Debug SMS] URL purificada enviada ao VirusTotal: '" + extractedUrl + "'");
        }

        if (extractedUrl == null) {
            SmsLinks smsSeguro = new SmsLinks(smsText, null, false, "SMS Seguro: Nenhuma URL encontrada.");
            return smsRepository.save(smsSeguro);
        }

        // Filtro local (Garante que se salvou na tb_links, o SMS também bloqueia)
        boolean isLocalMalicious = linkVerificationService.checkUrlIsMaliciousLocal(extractedUrl);
        if (isLocalMalicious) {
            SmsLinks smsBloqueadoLocal = new SmsLinks(smsText, extractedUrl, true, "Bloqueado: Link contido no SMS pertence a um domínio marcado como ameaça.");
            return smsRepository.save(smsBloqueadoLocal);
        }

        // Consulta externa na API
        boolean isMaliciousByVT = virusTotalService.checkUrlIsMalicious(extractedUrl);
        if (isMaliciousByVT) {
            linkVerificationService.verifyLink(extractedUrl); // Atualiza a Trie e salva no banco de dados de links maliciosos

            SmsLinks smsMalicioso = new SmsLinks(smsText, extractedUrl, true, "Bloqueado: Link malicioso detectado dentro do SMS, pela API VirusTotal.");
            return smsRepository.save(smsMalicioso);
        }

        SmsLinks smsLinkSeguro = new SmsLinks(smsText, extractedUrl, false, "SMS Verificado: O link contido na mensagem parece seguro.");
        return smsRepository.save(smsLinkSeguro);
    }

    public List<SmsLinks> getAllMessages() {
        return smsRepository.findAll();
    }

    public Optional<SmsLinks> getMessageById(Long id) {
        return smsRepository.findById(id);
    }
}