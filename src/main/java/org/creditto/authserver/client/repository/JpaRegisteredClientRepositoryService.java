package org.creditto.authserver.client.repository;

import jakarta.persistence.EntityNotFoundException;
import lombok.RequiredArgsConstructor;
import org.creditto.authserver.client.entity.OAuth2RegisteredClient;
import org.creditto.authserver.client.entity.RegisteredClientMapper;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

@Service
@RequiredArgsConstructor
@Transactional(readOnly = true)
public class JpaRegisteredClientRepositoryService implements RegisteredClientRepository {

    private final OAuth2RegisteredClientRepository oAuth2RegisteredClientRepository;
    private final RegisteredClientMapper mapper;

    @Override
    @Transactional
    public void save(RegisteredClient registeredClient) {
        OAuth2RegisteredClient entity = mapper.convertToEntity(registeredClient);
        oAuth2RegisteredClientRepository.save(entity);
    }

    @Override
    public RegisteredClient findById(String id) {
        return oAuth2RegisteredClientRepository.findById(id)
                .map(mapper::convertToRegisteredClient)
                .orElseThrow(EntityNotFoundException::new);
    }

    @Override
    public RegisteredClient findByClientId(String clientId) {
        return oAuth2RegisteredClientRepository.findByClientId(clientId)
                .map(mapper::convertToRegisteredClient)
                .orElseThrow(EntityNotFoundException::new);
    }
}
