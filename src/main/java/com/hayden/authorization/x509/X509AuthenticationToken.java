package com.hayden.authorization.x509;

import lombok.Getter;
import lombok.experimental.Delegate;
import org.springframework.security.authentication.AbstractAuthenticationToken;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2ClientAuthenticationToken;

import java.security.cert.X509Certificate;
import java.util.Collection;

@Getter
public class X509AuthenticationToken extends AbstractAuthenticationToken {

    @Delegate
    private final OAuth2ClientAuthenticationToken convert;
    private final X509Certificate certificate;

    /**
     * Creates a token with the supplied array of authorities.
     *
     * @param authorities the collection of <tt>GrantedAuthority</tt>s for the principal
     *                    represented by this authentication object.
     */
    public X509AuthenticationToken(Collection<? extends GrantedAuthority> authorities,
                                   OAuth2ClientAuthenticationToken convert,
                                   X509Certificate certificate) {
        super(authorities);
        this.convert = convert;
        this.certificate = certificate;
    }

}
