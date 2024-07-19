package com.hayden.authorization.password;

import com.hayden.authorization.auth_utils.ParameterUtils;
import com.hayden.authorization.client_credentials.ClientCredentialsParentExtractor;
import jakarta.servlet.http.HttpServletRequest;
import lombok.RequiredArgsConstructor;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.web.authentication.AuthenticationConverter;

import java.util.Optional;

@RequiredArgsConstructor
public class PasswordCredentialsGrantAuthenticationConverter implements AuthenticationConverter {

    private final ClientCredentialsParentExtractor parentExtractor;

    @Override
    public Authentication convert(HttpServletRequest request) {
        if(ParameterUtils.isGrantType(request, "X509_CERTIFICATE")) {
            return Optional.ofNullable(parentExtractor.convert(request))
                    .map(o -> new PasswordCredentialsGrantAuthenticationToken(o.getAuthorities(), o))
                    .orElse(null);
        }

        return null;
    }
}
