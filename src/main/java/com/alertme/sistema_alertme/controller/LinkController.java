package com.alertme.sistema_alertme.controller;

import com.alertme.sistema_alertme.model.Links;
import com.alertme.sistema_alertme.service.LinkVerificationService;
<<<<<<< HEAD
=======

import org.springframework.http.ResponseEntity;
>>>>>>> teste
import org.springframework.web.bind.annotation.*;

import java.util.List;

<<<<<<< HEAD
@RestController // Controlador REST
@RequestMapping("/api/links") // Rota base
=======
@RestController
@RequestMapping("/api/links")
@CrossOrigin(origins = "*")
>>>>>>> teste
public class LinkController {

    private final LinkVerificationService service;

<<<<<<< HEAD
    // Injeção de dependência do serviço
=======
>>>>>>> teste
    public LinkController(LinkVerificationService service) {
        this.service = service;
    }

    @PostMapping("/verificar")
<<<<<<< HEAD
    public Links verificar(@RequestBody Links LinkRequest) {
        return service.verifyLink(LinkRequest.getUrl());
=======
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
>>>>>>> teste
    }

    @GetMapping("/historico")
    public List<Links> getHistory() {
        return service.getHistory();
    }
}