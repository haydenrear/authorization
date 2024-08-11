package com.hayden.authorization.web_authn;

import com.hayden.authorization.auth_utils.ParameterUtils;
import com.hayden.authorization.client_credentials.ClientCredentialsParentExtractor;
import com.webauthn4j.springframework.security.WebAuthnAuthenticationToken;
import com.webauthn4j.springframework.security.WebAuthnProcessingFilter;
import jakarta.servlet.http.HttpServletRequest;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.core.Authentication;
import org.springframework.security.web.authentication.AuthenticationConverter;
import org.springframework.stereotype.Component;

import java.util.Optional;

@RequiredArgsConstructor
@Component
@Slf4j
public class OAuth2WebAuthnAuthenticationConverter implements AuthenticationConverter{

    private final ClientCredentialsParentExtractor parentExtractor;
    private final WebAuthnProcessingFilter webAuthnProcessingFilter;


    public OAuth2WebAuthnAuthenticationToken convert(HttpServletRequest request) {
        if(ParameterUtils.isGrantType(request, OAuth2WebAuthnGrantType.WEB_AUTHN)) {
            return Optional.ofNullable(webAuthnProcessingFilter.attemptAuthentication(request, null))
                    .filter(Authentication::isAuthenticated)
                    .flatMap(a -> a instanceof WebAuthnAuthenticationToken t
                            ? Optional.of(t)
                            : Optional.empty()
                    )
                    .flatMap(a -> Optional.ofNullable(parentExtractor.convert(request))
                            .map(c -> new OAuth2WebAuthnAuthenticationToken(a, c))
                    )
                    .orElse(null);
        }

        return null;
    }

}
