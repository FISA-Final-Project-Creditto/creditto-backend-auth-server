package org.creditto.authserver.auth.authentication;

import jakarta.servlet.http.HttpServletRequest;
import org.creditto.authserver.auth.constants.CustomGrantType;
import org.creditto.authserver.auth.constants.ParameterConstants;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.OAuth2Error;
import org.springframework.security.oauth2.core.OAuth2ErrorCodes;
import org.springframework.security.oauth2.core.endpoint.OAuth2ParameterNames;
import org.springframework.security.web.authentication.AuthenticationConverter;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;
import org.springframework.util.StringUtils;

import java.util.Map;

import static org.creditto.authserver.auth.constants.Constants.USER_AGENT;

/**
 * 요청에 대한 GrantType 검증 및 인증 요청 방식 검사 및 CertificateAuthenticationToken로 변경 후 반환
 */
public class CertificateGrantAuthenticationConverter implements AuthenticationConverter {

    @Override
    public Authentication convert(HttpServletRequest request) {
        String grantType = request.getParameter(OAuth2ParameterNames.GRANT_TYPE);

        AuthorizationGrantType authorizationGrantType = CustomGrantType.CERTIFICATE;

        // GrantType 검증 (Certificate)
        if (!authorizationGrantType.getValue().equals(grantType)) {
            return null;
        }

        // 파라미터 추출
        MultiValueMap<String, String> parameters = getParameterFromRequest(request);

        // serialNum 추출 및 검증
        String certificateSerial = getParameter(parameters, ParameterConstants.CERTIFICATE_SERIAL);
        String simplePassword = getParameter(parameters, ParameterConstants.SIMPLE_PASSWORD);
        String clientId = getParameter(parameters, ParameterConstants.CLIENT_ID);

        // 익명 인증 객체 생성
        // 해당 익명 인증 객체 생성 가능 여부를 판단하여 올바른 요청인지 검증
        CertificateAuthenticationToken token = CertificateAuthenticationToken.createAnonymousToken(certificateSerial, simplePassword, clientId);
        token.setDetails(RequestClientInfo.from(request.getRemoteAddr(), request.getHeader(USER_AGENT)));
        return token;
    }

    private static String getParameter(MultiValueMap<String, String> parameters, String parameterName) {
        String parameter = parameters.getFirst(parameterName);
        if (!StringUtils.hasText(parameter)) {
            throwOAuth2AuthError(
                    parameterName + " 파라미터 누락"
            );
        }

        return parameter;
    }

    private static MultiValueMap<String, String> getParameterFromRequest(HttpServletRequest request) {
        Map<String, String[]> parameterMap = request.getParameterMap();
        MultiValueMap<String, String> parameters = new LinkedMultiValueMap<>();

        parameterMap.forEach((key, values) -> {
            for (String value : values) {
                parameters.add(key, value);
            }
        });

        return parameters;
    }

    private static void throwOAuth2AuthError(String description) {
        OAuth2Error e = new OAuth2Error(OAuth2ErrorCodes.INVALID_REQUEST, description, null);
        throw new OAuth2AuthenticationException(e);
    }
}
