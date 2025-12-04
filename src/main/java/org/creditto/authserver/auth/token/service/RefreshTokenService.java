package org.creditto.authserver.auth.token.service;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.creditto.authserver.auth.authentication.RequestClientInfo;
import org.creditto.authserver.auth.token.domain.RefreshTokenSession;
import org.creditto.authserver.auth.token.exception.InvalidRefreshTokenException;
import org.creditto.authserver.auth.token.repository.RefreshTokenRepository;
import org.creditto.authserver.certificate.entity.Certificate;
import org.creditto.authserver.user.entity.User;
import org.springframework.security.oauth2.core.OAuth2RefreshToken;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.stereotype.Service;
import org.springframework.util.StringUtils;

@Slf4j
@Service
@RequiredArgsConstructor
public class RefreshTokenService {

    private final RefreshTokenRepository refreshTokenRepository;

    public void store(User user, Certificate certificate, RegisteredClient registeredClient, OAuth2RefreshToken refreshToken, RequestClientInfo clientInfo) {
        if (refreshToken == null) {
            return;
        }

        RefreshTokenSession session = RefreshTokenSession.builder()
                .userId(user.getId().toString())
                .username(user.getName())
                .roles(user.mapRoleListToString())
                .certificateId(certificate.getId().toString())
                .certificateSerial(certificate.getSerialNumber())
                .countryCode(user.getCountryCode())
                .phoneNo(user.getPhoneNo())
                .clientId(registeredClient.getClientId())
                .tokenValue(refreshToken.getTokenValue())
                .issuedAt(refreshToken.getIssuedAt())
                .expiresAt(refreshToken.getExpiresAt())
                .sessionId(refreshToken.getTokenValue())
                .ipAddress(clientInfo != null ? clientInfo.ipAddress() : null)
                .userAgent(clientInfo != null ? clientInfo.userAgent() : null)
                .build();

        refreshTokenRepository.save(session);
        log.debug("RefreshTokenSession 저장 완료 - userId: {}, clientId: {}", session.userId(), registeredClient.getClientId());
    }

    public RefreshTokenSession validate(String refreshTokenValue, String clientId) {
        RefreshTokenSession session = refreshTokenRepository.findByToken(refreshTokenValue)
                .orElseThrow(InvalidRefreshTokenException::new);

        if (!session.clientId().equals(clientId)) {
            throw new InvalidRefreshTokenException("클라이언트 정보가 일치하지 않습니다.");
        }

        return session;
    }

    public RefreshTokenSession rotate(RefreshTokenSession session, OAuth2RefreshToken newRefreshToken, RequestClientInfo clientInfo) {
        if (newRefreshToken == null) {
            return session;
        }

        refreshTokenRepository.deleteByToken(session.tokenValue());

        RefreshTokenSession rotated = session.rotate(
                newRefreshToken.getTokenValue(),
                newRefreshToken.getIssuedAt(),
                newRefreshToken.getExpiresAt(),
                clientInfo != null ? clientInfo.ipAddress() : null,
                clientInfo != null ? clientInfo.userAgent() : null
        );

        refreshTokenRepository.save(rotated);
        return rotated;
    }

    public void revoke(String refreshTokenValue) {
        if (!StringUtils.hasText(refreshTokenValue)) {
            return;
        }
        refreshTokenRepository.deleteByToken(refreshTokenValue);
    }
}
