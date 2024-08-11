package com.hayden.authorization.x509;

import com.hayden.authorization.oauth2.OAuth2CustomAuthenticationToken;
import lombok.Getter;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2ClientAuthenticationToken;
import org.springframework.security.web.authentication.preauth.PreAuthenticatedAuthenticationToken;

import java.security.cert.X509Certificate;
import java.util.Collection;

@Getter
public class X509AuthenticationToken extends PreAuthenticatedAuthenticationToken implements OAuth2CustomAuthenticationToken {

    private final OAuth2ClientAuthenticationToken clientAuthentication;

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
        super(certificate.getIssuerX500Principal(), certificate, authorities);
        this.clientAuthentication = convert;
        this.certificate = certificate;
    }

    @Override
    public Collection<GrantedAuthority> getAuthorities() {
        return super.getAuthorities();
    }

    @Override
    public String getName() {
        return certificate.getSubjectX500Principal().getName();
    }

    @Override
    public Object getCredentials() {
        return certificate;
    }

    @Override
    public Object getPrincipal() {
        return certificate.getSubjectX500Principal();
    }

    @Override
    public boolean isAuthenticated() {
        return true;
    }

    @Override
    public void setAuthenticated(boolean authenticated) {
        super.setAuthenticated(authenticated);
    }

}
