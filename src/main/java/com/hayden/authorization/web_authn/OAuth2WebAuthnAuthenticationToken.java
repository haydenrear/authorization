package com.hayden.authorization.web_authn;

import com.hayden.authorization.oauth2.OAuth2CustomAuthenticationToken;
import com.webauthn4j.springframework.security.WebAuthnAuthenticationToken;
import lombok.Getter;
import lombok.Setter;
import org.springframework.security.authentication.AbstractAuthenticationToken;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2ClientAuthenticationToken;

public class OAuth2WebAuthnAuthenticationToken extends AbstractAuthenticationToken implements OAuth2CustomAuthenticationToken {

    @Getter
    @Setter
    private WebAuthnAuthenticationToken credential;
    @Getter
    @Setter
    private OAuth2ClientAuthenticationToken clientAuthentication;

    public OAuth2WebAuthnAuthenticationToken(WebAuthnAuthenticationToken credential,
                                             OAuth2ClientAuthenticationToken clientToken) {
        super(credential.getAuthorities());
        this.credential = credential;
        this.clientAuthentication = clientToken;
    }

    @Override
    public Object getCredentials() {
        return credential;
    }

    @Override
    public Object getPrincipal() {
        return credential.getPrincipal();
    }


}