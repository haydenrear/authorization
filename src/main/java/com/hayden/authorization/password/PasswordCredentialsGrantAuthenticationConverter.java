package com.hayden.authorization.password;

import com.hayden.authorization.auth_utils.ParameterUtils;
import com.hayden.authorization.client_credentials.ClientCredentialsParentExtractor;
import jakarta.servlet.http.HttpServletRequest;
import lombok.RequiredArgsConstructor;
import org.springframework.lang.Nullable;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.server.authorization.web.authentication.ClientSecretBasicAuthenticationConverter;
import org.springframework.security.web.authentication.AuthenticationConverter;

import java.util.Map;
import java.util.Optional;

import static org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter.SPRING_SECURITY_FORM_PASSWORD_KEY;
import static org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter.SPRING_SECURITY_FORM_USERNAME_KEY;

@RequiredArgsConstructor
public class PasswordCredentialsGrantAuthenticationConverter implements AuthenticationConverter {

    private final ClientCredentialsParentExtractor parentExtractor;

    private final ClientSecretBasicAuthenticationConverter clientSecretBasicAuthenticationConverter = new ClientSecretBasicAuthenticationConverter();

    private static final String USERNAME_PARAMETER = SPRING_SECURITY_FORM_USERNAME_KEY;

    private static final String PASSWORD_PARAMETER = SPRING_SECURITY_FORM_PASSWORD_KEY;

    @Override
    public Authentication convert(HttpServletRequest request) {
        if(ParameterUtils.isGrantType(request, AuthorizationGrantType.PASSWORD)) {
            return Optional.ofNullable(parentExtractor.convert(request))
                    .map(o -> Map.entry(o, unauthenticated(request)))
                    .map(o -> new PasswordCredentialsGrantAuthenticationToken(o.getKey().getAuthorities(), o.getValue(), o.getKey()))
                    .orElse(null);
        }

        return null;
    }

    public UsernamePasswordAuthenticationToken unauthenticated(HttpServletRequest request) {
        String username = obtainUsername(request);
        username = (username != null) ? username.trim() : "";
        String password = obtainPassword(request);
        password = (password != null) ? password : "";
        return UsernamePasswordAuthenticationToken.unauthenticated(username, password);
    }

    @Nullable
    protected String obtainPassword(HttpServletRequest request) {
        return Optional.ofNullable(request.getParameter(PASSWORD_PARAMETER))
                .or(() -> {
                    var converted = clientSecretBasicAuthenticationConverter.convert(request);
                    return Optional.ofNullable(converted)
                            .flatMap(o -> Optional.ofNullable(o.getCredentials()))
                            .map(Object::toString);
                })
                .orElse(null);
    }

    @Nullable
    protected String obtainUsername(HttpServletRequest request) {
        return Optional.ofNullable(request.getParameter(USERNAME_PARAMETER))
                .or(() -> {
                    var converted = clientSecretBasicAuthenticationConverter.convert(request);
                    return Optional.ofNullable(converted)
                            .flatMap(o -> Optional.ofNullable(o.getPrincipal()))
                            .map(Object::toString);
                })
                .orElse(null);
    }

}
