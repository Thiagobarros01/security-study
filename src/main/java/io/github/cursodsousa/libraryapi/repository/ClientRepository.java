package io.github.cursodsousa.libraryapi.repository;

import io.github.cursodsousa.libraryapi.model.Client;
import org.springframework.data.jpa.repository.JpaRepository;

public interface ClientRepository extends JpaRepository<Client, Long> {
    Client findByClientId(String clientId);
}
