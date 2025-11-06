package org.creditto.authserver.auth.config;

import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.source.ImmutableJWKSet;
import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.proc.SecurityContext;
import lombok.RequiredArgsConstructor;
import org.creditto.authserver.auth.CustomAuthenticationEntryPoint;
import org.creditto.authserver.auth.authentication.CertificateGrantAuthenticationConverter;
import org.creditto.authserver.auth.jwt.RsaKeyProperties;
import org.creditto.authserver.auth.jwt.RsaKeyUtil;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.JwtEncoder;
import org.springframework.security.oauth2.jwt.NimbusJwtEncoder;
import org.springframework.security.oauth2.server.authorization.config.annotation.web.configuration.OAuth2AuthorizationServerConfiguration;
import org.springframework.security.oauth2.server.authorization.config.annotation.web.configurers.OAuth2AuthorizationServerConfigurer;
import org.springframework.security.oauth2.server.authorization.settings.AuthorizationServerSettings;
import org.springframework.security.web.SecurityFilterChain;

import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.util.UUID;

@Configuration
@EnableWebSecurity
@RequiredArgsConstructor
@EnableConfigurationProperties(RsaKeyProperties.class)
public class AuthorizationServerConfig {

    @Value("${AUTH_SERVER_URL}")
    private String authServerUrl;

    private final CustomAuthenticationEntryPoint customAuthenticationEntryPoint;
    private final RsaKeyUtil rsaKeyUtil;

    @Bean
    @Order(1)
    // OAuth2 관련 엔드포인트 요청 처리 필처
    public SecurityFilterChain authorizationServerSecurityFilterChain(HttpSecurity http) throws Exception {

        // 1. Configurer 인스턴스 생성
        OAuth2AuthorizationServerConfigurer authorizationServerConfigurer = OAuth2AuthorizationServerConfigurer.authorizationServer();

        http
                .securityMatcher(authorizationServerConfigurer.getEndpointsMatcher()) // OAuth2 관련 엔드포인트만 관리
                .with(authorizationServerConfigurer, authorizationServer -> // Authorization Server 설정 적용 및 커스터마이징
                        authorizationServer
                                .tokenEndpoint(tokenEndpoint ->
                                        tokenEndpoint.accessTokenRequestConverter(
                                                new CertificateGrantAuthenticationConverter() // 인증서 기반 인증 처리하도록 Converter 지정
                                        )
                                )
                                .oidc(Customizer.withDefaults()) // OpenID Connect 활성화
                )
                // 이외 요청에 대해선 인증처리
                .authorizeHttpRequests(authorize ->
                        authorize.anyRequest().authenticated()
                );
        http
                .exceptionHandling(exceptions -> exceptions
                        .authenticationEntryPoint(customAuthenticationEntryPoint)
                )
                .oauth2ResourceServer(resourceServer -> resourceServer
                        .jwt(Customizer.withDefaults())
                );

        return http.build();
    }

    @Bean
    @Order(2)
    // OAuth2 이외 요청들에 대한 기본 요청 관련 필터
    public SecurityFilterChain defaultSecurityFilterChain(HttpSecurity http)
            throws Exception {
        http
                .authorizeHttpRequests(authorize -> authorize
                        .requestMatchers("/api/certificate/**").permitAll()
                        .requestMatchers("/api/client/**").permitAll()
                        .requestMatchers("/oauth2/token").permitAll()
                        .anyRequest().authenticated()
                )
                .csrf(csrf -> csrf
                        .ignoringRequestMatchers("/api/certificate/**", "/oauth2/token", "/api/client/**")
                )
                .exceptionHandling(exceptions -> exceptions
                        .authenticationEntryPoint(customAuthenticationEntryPoint)
                );

        return http.build();
    }

    @Bean
    public JWKSource<SecurityContext> jwkSource() {
        try {
            RSAPrivateKey privateKey = rsaKeyUtil.getPrivateKey();

            RSAPublicKey publicKey = rsaKeyUtil.getPublicKey();

            // 3. JWK 생성
            RSAKey rsaKey = new RSAKey.Builder(publicKey)
                    .privateKey(privateKey)
                    .keyID(UUID.randomUUID().toString())
                    .build();

            JWKSet jwkSet = new JWKSet(rsaKey);
            return new ImmutableJWKSet<>(jwkSet);

        } catch (Exception e) {
            throw new IllegalStateException("Failed to load RSA keys", e);
        }
    }

    @Bean
    public JwtDecoder jwtDecoder(JWKSource<SecurityContext> jwkSource) {
        return OAuth2AuthorizationServerConfiguration.jwtDecoder(jwkSource);
    }

    @Bean
    public JwtEncoder jwtEncoder(JWKSource<SecurityContext> jwkSource) {
        return new NimbusJwtEncoder(jwkSource);
    }

    @Bean
    public AuthorizationServerSettings authorizationServerSettings() {
        return AuthorizationServerSettings.builder()
                .issuer(authServerUrl)
                .build();
    }
}
