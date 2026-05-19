package com.alertme.sistema_alertme.controller;

import com.alertme.sistema_alertme.model.Links;
import com.alertme.sistema_alertme.service.LinkVerificationService;
import org.springframework.web.bind.annotation.*;

import java.util.List;

@RestController // Indica que esta classe é um controlador REST
@RequestMapping("/api/links") // Define a rota base
public class LinkController {

    private final LinkVerificationService service;

    // Injeção de dependência do serviço
    public LinkController(LinkVerificationService service) {
        this.service = service;
    }

    @PostMapping("/verificar")
    public Links verificar(@RequestBody Links LinkRequest) {
        return service.verifyLink(LinkRequest.getUrl());
    }

    @GetMapping("/historico")
    public List<Links> getHistory() {
        return service.getHistory();
    }
}