package com.alertme.sistema_alertme.controller;

import com.alertme.sistema_alertme.model.Links;
import com.alertme.sistema_alertme.service.LinkVerificationService;

import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.List;

@RestController
@RequestMapping("/api/links")
@CrossOrigin(origins = "*")
public class LinkController {

    private final LinkVerificationService service;

    public LinkController(LinkVerificationService service) {
        this.service = service;
    }

    @PostMapping("/verificar")
    public ResponseEntity<Links> verificar(@RequestBody java.util.Map<String, String> request) {
        // Validação de segurança para evitar NullPointerException
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
}