package com.hayden.authorization.oauth2;

import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2ClientAuthenticationToken;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;

import java.util.HashSet;
import java.util.Optional;
import java.util.Set;

public interface OAuth2CustomAuthenticationToken extends Authentication {

    OAuth2ClientAuthenticationToken getClientAuthentication();

    default Set<String> getScopes() {
        return Optional.ofNullable(getClientAuthentication().getRegisteredClient())
                .map(RegisteredClient::getScopes)
                .orElse(new HashSet<>());
    }

}
