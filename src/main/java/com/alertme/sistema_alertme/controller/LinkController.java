package com.alertme.sistema_alertme.controller;

import com.alertme.sistema_alertme.model.Links;
import com.alertme.sistema_alertme.repository.LinkRepository;
import com.alertme.sistema_alertme.repository.SmsRepository;
import com.alertme.sistema_alertme.service.LinkVerificationService;

import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.HashMap;
import java.util.List;
import java.util.Map;

@RestController
@RequestMapping("/api/links")
@CrossOrigin(origins = "https://alertme-wicd.onrender.com")
public class LinkController {

    private final LinkVerificationService service;
    private final LinkRepository linkRepository;
    private final SmsRepository smsRepository;

    public LinkController(LinkVerificationService service, LinkRepository linkRepository, SmsRepository smsRepository) {
        this.service = service;
        this.linkRepository = linkRepository;
        this.smsRepository = smsRepository;
    }

    @PostMapping("/verificar")
    public ResponseEntity<Links> verificar(@RequestBody Map<String, String> request) {
        if (request == null || !request.containsKey("url")) {
            return ResponseEntity.badRequest().build();
        }

        String urlValue = request.get("url");
        if (urlValue == null || urlValue.trim().isEmpty()) {
            return ResponseEntity.badRequest().build();
        }

        Links resultado = service.verifyLink(urlValue);
        return ResponseEntity.ok(resultado);
    }

    @GetMapping("/historico")
    public List<Links> getHistory() {
        return service.getHistory();
    }

    // Endpoint administrativo temporário para limpar o banco de dados via requisição
    @DeleteMapping("/limpar-banco-admin-temporario")
    public ResponseEntity<Map<String, String>> limparBancoCompleto() {
        Map<String, String> resposta = new HashMap<>();
        try {
            // Remove os registros de ambas as tabelas respeitando possíveis chaves/relacionamentos
            smsRepository.deleteAll();
            linkRepository.deleteAll();

            resposta.put("status", "sucesso");
            resposta.put("mensagem", "Banco de dados limpo com sucesso");
            return ResponseEntity.ok(resposta);
            
        } catch (Exception e) {
            resposta.put("status", "erro");
            resposta.put("mensagem", "Falha ao limpar o banco: " + e.getMessage());
            return ResponseEntity.internalServerError().body(resposta);
        }
    }
}