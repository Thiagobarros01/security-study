package io.github.cursodsousa.libraryapi.controller;

import io.github.cursodsousa.libraryapi.model.Client;
import io.github.cursodsousa.libraryapi.service.ClientService;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/clients")
@RequiredArgsConstructor
public class ClientController {

    private final ClientService clientService;


    @PostMapping
    public ResponseEntity<Void> salvar(@RequestBody Client client) {
        clientService.salvar(client);
        return ResponseEntity.status(HttpStatus.CREATED).build();
    }

    @GetMapping("{clientId}")
    public ResponseEntity<Client> buscarPorClientId(@PathVariable String clientId){
        return ResponseEntity.ok(clientService.obterPorClientID(clientId));
    }
}
