package com.hayden.authorization.client_credentials;

import jakarta.servlet.http.HttpServletRequest;
import lombok.RequiredArgsConstructor;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2ClientAuthenticationToken;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.security.web.authentication.AuthenticationConverter;
import org.springframework.stereotype.Component;

import java.util.Map;
import java.util.Optional;

@Component
@RequiredArgsConstructor
public class ClientCredentialsParentExtractor implements AuthenticationConverter {

    private final AuthenticationConverter parentDelegatingAuthenticationConverter;
    private final RegisteredClientRepository registeredClientRepository;


    @Override
    public OAuth2ClientAuthenticationToken convert(HttpServletRequest request) {
        return extractParentToken(request)
                .orElse(null);
    }

    private Optional<OAuth2ClientAuthenticationToken> extractParentToken(HttpServletRequest request) {
        return oAuth2ClientAuthenticationToken(request)
                .flatMap(convert -> Optional.ofNullable(registeredClientRepository.findByClientId(convert.getPrincipal().toString()))
                        .flatMap(r -> Optional.ofNullable(convert.getCredentials())
                                .map(c -> Map.entry(c, r))
                                .map(c -> new OAuth2ClientAuthenticationToken(
                                        c.getValue(),
                                        ClientAuthenticationMethod.CLIENT_SECRET_POST,
                                        c.getKey()
                                ))));
    }

    private Optional<OAuth2ClientAuthenticationToken> oAuth2ClientAuthenticationToken(HttpServletRequest request) {
        return Optional.ofNullable(parentDelegatingAuthenticationConverter.convert(request))
                .flatMap(a -> a instanceof  OAuth2ClientAuthenticationToken o
                        ? Optional.of(o)
                        : Optional.empty()
                );
    }

}
