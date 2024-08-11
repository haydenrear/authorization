package com.hayden.authorization.auth_utils;

import jakarta.servlet.http.HttpServletRequest;
import lombok.experimental.UtilityClass;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.endpoint.OAuth2ParameterNames;

import java.util.Objects;
import java.util.Optional;

@UtilityClass
public class ParameterUtils {


    public static Optional<String> grantType(HttpServletRequest request) {
        return Optional.ofNullable(request.getParameterValues(OAuth2ParameterNames.GRANT_TYPE))
                .map(s -> {
                    if (s.length > 1) {
                        throw new UnsupportedOperationException("Grant type contained more than one parameter value!");
                    }

                    return s[0];
                });
    }

    public static boolean isGrantType(HttpServletRequest request, AuthorizationGrantType grantType) {
        return isGrantType(request, grantType.getValue());
    }

    public static boolean isGrantType(HttpServletRequest request, String grantType) {
        return grantType(request)
                .filter(s -> s.equals(grantType))
                .isPresent();
    }
}
