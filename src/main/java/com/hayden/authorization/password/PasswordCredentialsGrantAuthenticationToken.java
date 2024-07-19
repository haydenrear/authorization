package com.hayden.authorization.password;

import lombok.Getter;
import lombok.experimental.Delegate;
import org.springframework.security.authentication.AbstractAuthenticationToken;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2ClientAuthenticationToken;

import java.util.Collection;

@Getter
public class PasswordCredentialsGrantAuthenticationToken extends AbstractAuthenticationToken {

    @Delegate
    private final OAuth2ClientAuthenticationToken convert;

    /**
     * Creates a token with the supplied array of authorities.
     *
     * @param authorities the collection of <tt>GrantedAuthority</tt>s for the principal
     *                    represented by this authentication object.
     */
    public PasswordCredentialsGrantAuthenticationToken(Collection<? extends GrantedAuthority> authorities, OAuth2ClientAuthenticationToken convert) {
        super(authorities);
        this.convert = convert;
    }

}
