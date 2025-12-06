package org.creditto.authserver.domain.client.repository;

import lombok.RequiredArgsConstructor;
import org.creditto.authserver.domain.client.entity.OAuth2RegisteredClient;
import org.creditto.authserver.domain.client.entity.RegisteredClientMapper;
import org.springframework.lang.Nullable;
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
    @Nullable
    public RegisteredClient findById(String id) {
        return oAuth2RegisteredClientRepository.findById(id)
                .map(mapper::convertToRegisteredClient)
                .orElse(null);
    }

    @Override
    @Nullable
    public RegisteredClient findByClientId(String clientId) {
        return oAuth2RegisteredClientRepository.findByClientId(clientId)
                .map(mapper::convertToRegisteredClient)
                .orElse(null);
    }
}
