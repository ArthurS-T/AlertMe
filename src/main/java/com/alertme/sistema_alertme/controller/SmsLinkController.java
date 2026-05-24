package com.alertme.sistema_alertme.controller;

import com.alertme.sistema_alertme.model.SmsLinks;
import com.alertme.sistema_alertme.service.SmsVerificationService;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;
import java.util.Map;
import java.util.List;

@RestController
@RequestMapping("/api/sms")
public class SmsLinkController {

    private final SmsVerificationService smsVerificationService;

    public SmsLinkController(SmsVerificationService smsVerificationService) {
        this.smsVerificationService = smsVerificationService;
    }

    @GetMapping("/historico")
    public ResponseEntity<List<SmsLinks>> listarTodosSms() {
        return ResponseEntity.ok(smsVerificationService.getAllMessages());
    }

    @PostMapping("/verificar")
    public ResponseEntity<SmsLinks> verificarSms(@RequestBody Map<String, String> request) {
        if (request == null || !request.containsKey("smsText")) { 
            return ResponseEntity.badRequest().build(); 
        }

        // Validação para garantir que o texto não seja vazio ou em branco
        String smsText = request.get("smsText");
        if (smsText == null || smsText.trim().isEmpty()) {
            return ResponseEntity.badRequest().body(
                    new SmsLinks("Texto vazio", null, false, "Corpo da mensagem sem conteúdo válido."));
        }

        SmsLinks result = smsVerificationService.verifySmsText(smsText);
        return ResponseEntity.ok(result);
    }
}