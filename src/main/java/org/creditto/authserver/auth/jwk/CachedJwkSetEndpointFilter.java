package org.creditto.authserver.auth.jwk;

import com.nimbusds.jose.jwk.JWKSelector;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.proc.SecurityContext;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.extern.slf4j.Slf4j;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.io.PrintWriter;
import java.util.List;

@Slf4j
public class CachedJwkSetEndpointFilter extends OncePerRequestFilter {

    private final JWKSource<SecurityContext> jwkSource;
    private final String endpointUri;
    private final JWKSelector jwkSelector = new JWKSelector(new com.nimbusds.jose.jwk.JWKMatcher.Builder().build());
    private final JwkCacheService jwkCacheService;

    public CachedJwkSetEndpointFilter(
            JWKSource<SecurityContext> jwkSource,
            JwkCacheService jwkCacheService,
            String endpointUri
    ) {
        this.jwkSource = jwkSource;
        this.jwkCacheService = jwkCacheService;
        this.endpointUri = endpointUri;
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain)
            throws ServletException, IOException {
        if (!matches(request)) {
            filterChain.doFilter(request, response);
            return;
        }

        try {
            String jwkJson = jwkCacheService.getCachedJwk()
                    .orElseGet(this::loadAndCacheJwk);
            writeResponse(response, jwkJson);
        } catch (Exception ex) {
            log.error("JWK 응답 생성 실패", ex);
            response.sendError(HttpServletResponse.SC_INTERNAL_SERVER_ERROR, "Unable to load JWK set");
        }
    }

    private String loadAndCacheJwk() {
        try {
            List<com.nimbusds.jose.jwk.JWK> jwkList = jwkSource.get(jwkSelector, null);
            String jwkJson = new JWKSet(jwkList).toString();
            jwkCacheService.cacheJwk(jwkJson);
            return jwkJson;
        } catch (Exception ex) {
            throw new IllegalStateException("JWK 조회에 실패했습니다: " + ex.getMessage(), ex);
        }
    }

    private void writeResponse(HttpServletResponse response, String jwkJson) throws IOException {
        response.setContentType("application/json");
        response.setCharacterEncoding("UTF-8");
        PrintWriter writer = response.getWriter();
        writer.write(jwkJson);
        writer.flush();
    }

    private boolean matches(HttpServletRequest request) {
        return "GET".equalsIgnoreCase(request.getMethod())
                && request.getRequestURI().equals(endpointUri);
    }
}
