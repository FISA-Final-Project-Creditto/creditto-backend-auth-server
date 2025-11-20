package org.creditto.authserver.auth.config;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.CorsConfigurationSource;
import org.springframework.web.cors.UrlBasedCorsConfigurationSource;

import java.util.List;

@Configuration
public class CorsConfig {

    @Value("${CLIENT_IP}")
    private String clientIp;

    @Bean
    public CorsConfigurationSource corsConfigurationSource() {
        CorsConfiguration config = new CorsConfiguration();

        // 허용할 Origin
        config.setAllowedOrigins(
                List.of(clientIp)
        );

        // 허용할 HTTP 메서드
        config.setAllowedMethods(
                List.of("GET", "POST", "PUT", "DELETE", "PATCH", "OPTIONS")
        );

        // 허용할 헤더들 (Authorization, Content-Type 등)
        config.setAllowedHeaders(List.of("*"));

        // 응답에서 노출하고 싶은 헤더 (선택)
        config.setExposedHeaders(List.of("Authorization", "Content-Type"));

        // 쿠키/Authorization 헤더 같이 보낼 거면 true
        config.setAllowCredentials(true);

        UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
        source.registerCorsConfiguration("/**", config);
        return source;
    }
}
