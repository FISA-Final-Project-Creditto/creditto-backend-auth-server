package org.creditto.authserver.auth.config;

import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.source.ImmutableJWKSet;
import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.proc.SecurityContext;
import lombok.RequiredArgsConstructor;
import org.creditto.authserver.auth.authentication.CertificateGrantAuthenticationConverter;
import org.creditto.authserver.auth.authentication.CertificateGrantAuthenticationProvider;
import org.creditto.authserver.auth.jwk.CachedJwkSetEndpointFilter;
import org.creditto.authserver.auth.jwk.JwkCacheService;
import org.creditto.authserver.auth.jwt.CertificateOAuth2TokenGenerator;
import org.creditto.authserver.auth.jwt.RsaKeyProperties;
import org.creditto.authserver.auth.jwt.RsaKeyUtil;
import org.creditto.authserver.auth.token.service.RefreshTokenService;
import org.creditto.authserver.domain.certificate.service.CertificateService;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.boot.web.servlet.FilterRegistrationBean;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.JwtEncoder;
import org.springframework.security.oauth2.jwt.NimbusJwtEncoder;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationService;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.config.annotation.web.configuration.OAuth2AuthorizationServerConfiguration;
import org.springframework.security.oauth2.server.authorization.config.annotation.web.configurers.OAuth2AuthorizationServerConfigurer;
import org.springframework.security.oauth2.server.authorization.settings.AuthorizationServerSettings;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.core.AuthenticationException;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.web.servlet.HandlerExceptionResolver;

import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;

import static org.creditto.authserver.global.response.error.ErrorMessage.FAILED_LOAD_RSA;

@Configuration
@EnableWebSecurity
@RequiredArgsConstructor
@EnableConfigurationProperties(RsaKeyProperties.class)
public class AuthorizationServerConfig {

    @Value("${AUTH_SERVER_URL}")
    private String authServerUrl;

    @Value("${JWK_KEY_ID}")
    private String keyId;

    private final CustomAuthenticationEntryPoint customAuthenticationEntryPoint;
    private final CustomAccessDeniedHandler customAccessDeniedHandler;
    private final RsaKeyUtil rsaKeyUtil;
    private final HandlerExceptionResolver handlerExceptionResolver;

    @Bean
    @Order(1)
    // OAuth2 관련 엔드포인트 요청 처리 필처
    public SecurityFilterChain authorizationServerSecurityFilterChain(
            HttpSecurity http,
            CertificateGrantAuthenticationProvider certificateGrantAuthenticationProvider) throws Exception {

        // 1. Configurer 인스턴스 생성
        OAuth2AuthorizationServerConfigurer authorizationServerConfigurer = OAuth2AuthorizationServerConfigurer.authorizationServer();

        http
                .securityMatcher(authorizationServerConfigurer.getEndpointsMatcher()) // OAuth2 관련 엔드포인트만 관리
                .with(authorizationServerConfigurer, authorizationServer -> // Authorization Server 설정 적용 및 커스터마이징
                        authorizationServer
                                .tokenEndpoint(tokenEndpoint ->
                                        tokenEndpoint
                                                .accessTokenRequestConverter(
                                                        new CertificateGrantAuthenticationConverter() // 인증서 기반 인증 처리하도록 Converter 지정
                                                )
                                                .errorResponseHandler(this::handleTokenError)
                                                .authenticationProvider(certificateGrantAuthenticationProvider) // 인증서 Grant Provider 등록
                                )
                                .oidc(Customizer.withDefaults()) // OpenID Connect 활성화
                )
                .cors(Customizer.withDefaults())
                // 이외 요청에 대해선 인증처리
                .authorizeHttpRequests(authorize ->
                        authorize.anyRequest().authenticated()
                );
        http
                .exceptionHandling(exceptions -> exceptions
                        .authenticationEntryPoint(customAuthenticationEntryPoint)
                        .accessDeniedHandler(customAccessDeniedHandler)
                )
                .oauth2ResourceServer(resourceServer -> resourceServer
                        .jwt(Customizer.withDefaults())
                        .authenticationEntryPoint(customAuthenticationEntryPoint)
                        .accessDeniedHandler(customAccessDeniedHandler)
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
                        .requestMatchers("/api/user/**").permitAll()
                        .requestMatchers("/api/certificate/**").permitAll()
                        .requestMatchers("/api/client/**").permitAll()
                        .requestMatchers("/api/auth/**").permitAll()
                        .requestMatchers("/actuator/health").permitAll()
                        .requestMatchers("/actuator/info").permitAll()
                        .anyRequest().authenticated()
                )
                .csrf(csrf -> csrf
                        .ignoringRequestMatchers("/api/user/**", "/api/certificate/**", "/api/client/**", "/api/auth/token/refresh", "/actuator/**")
                )
                .cors(Customizer.withDefaults())
                .exceptionHandling(exceptions -> exceptions
                        .authenticationEntryPoint(customAuthenticationEntryPoint)
                        .accessDeniedHandler(customAccessDeniedHandler)
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
                    .keyID(keyId)
                    .build();

            JWKSet jwkSet = new JWKSet(rsaKey);
            return new ImmutableJWKSet<>(jwkSet);

        } catch (Exception e) {
            throw new IllegalStateException(FAILED_LOAD_RSA, e);
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

    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }

    /**
     * 인증서 기반 Grant Authentication Provider
     */
    @Bean
    public CertificateGrantAuthenticationProvider certificateGrantAuthenticationProvider(
            CertificateService certificateService,
            RegisteredClientRepository registeredClientRepository,
            OAuth2AuthorizationService authorizationService,
            CertificateOAuth2TokenGenerator certificateTokenGenerator,
            RefreshTokenService refreshTokenService
    ) {
        return new CertificateGrantAuthenticationProvider(
                certificateService,
                registeredClientRepository,
                authorizationService,
                certificateTokenGenerator,
                refreshTokenService
        );
    }

    // MVC 예외 위임
    private void handleTokenError(HttpServletRequest request, HttpServletResponse response, AuthenticationException exception) {
        handlerExceptionResolver.resolveException(request, response, null, exception);
    }

    @Bean
    public FilterRegistrationBean<CachedJwkSetEndpointFilter> cachedJwkSetEndpointFilter(
            JWKSource<SecurityContext> jwkSource,
            JwkCacheService jwkCacheService,
            AuthorizationServerSettings authorizationServerSettings
    ) {
        CachedJwkSetEndpointFilter filter = new CachedJwkSetEndpointFilter(
                jwkSource,
                jwkCacheService,
                authorizationServerSettings.getJwkSetEndpoint()
        );
        FilterRegistrationBean<CachedJwkSetEndpointFilter> registration = new FilterRegistrationBean<>(filter);
        registration.setOrder(0);
        registration.addUrlPatterns(authorizationServerSettings.getJwkSetEndpoint());
        return registration;
    }
}
