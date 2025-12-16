package io.github.cursodsousa.libraryapi.service;

import io.github.cursodsousa.libraryapi.model.Client;
import io.github.cursodsousa.libraryapi.repository.ClientRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

@Service
@RequiredArgsConstructor
public class ClientService {

    private final ClientRepository clientRepository;
    private final PasswordEncoder passwordEncoder;

    @Transactional
    public Client salvar(Client client) {
        String senhaCriptografada = passwordEncoder.encode(client.getClientSecret());
        client.setClientSecret(senhaCriptografada);
        return clientRepository.save(client);
    }

    @Transactional(readOnly = true)
    public Client obterPorClientID(String clientID) {
        return clientRepository.findByClientId(clientID);
    }



}
