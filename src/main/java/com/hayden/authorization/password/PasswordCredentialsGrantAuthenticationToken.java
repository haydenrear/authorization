package com.hayden.authorization.password;

import com.hayden.authorization.oauth2.OAuth2CustomAuthenticationToken;
import lombok.Getter;
import lombok.Setter;
import org.springframework.security.authentication.AbstractAuthenticationToken;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2ClientAuthenticationToken;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.util.Assert;

import java.util.Collection;
import java.util.HashSet;
import java.util.Optional;
import java.util.Set;

@Getter
public class PasswordCredentialsGrantAuthenticationToken extends AbstractAuthenticationToken implements OAuth2CustomAuthenticationToken {

    private OAuth2ClientAuthenticationToken clientAuthentication;

    @Setter
    private UsernamePasswordAuthenticationToken usernamePasswordAuthenticationToken;


    /**
     * Creates a token with the supplied array of authorities.
     *
     * @param authorities the collection of <tt>GrantedAuthority</tt>s for the principal
     *                    represented by this authentication object.
     */
    public PasswordCredentialsGrantAuthenticationToken(Collection<? extends GrantedAuthority> authorities,
                                                       UsernamePasswordAuthenticationToken authentication,
                                                       OAuth2ClientAuthenticationToken convert) {
        super(authorities);
        this.usernamePasswordAuthenticationToken = authentication;
        this.clientAuthentication = convert;
    }

    public PasswordCredentialsGrantAuthenticationToken(PasswordCredentialsGrantAuthenticationToken other) {
        super(other.getAuthorities());
        this.usernamePasswordAuthenticationToken = other.getUsernamePasswordAuthenticationToken();
        this.clientAuthentication = other.getClientAuthentication();
        this.setAuthenticated(true);
    }


    @Override
    public Object getCredentials() {
        return this.usernamePasswordAuthenticationToken.getCredentials();
    }

    @Override
    public Object getPrincipal() {
        return this.usernamePasswordAuthenticationToken.getPrincipal();
    }

    @Override
    public Collection<GrantedAuthority> getAuthorities() {
        return usernamePasswordAuthenticationToken.getAuthorities();
    }

    @Override
    public boolean isAuthenticated() {
        return usernamePasswordAuthenticationToken.isAuthenticated() && clientAuthentication.isAuthenticated();
    }

    @Override
    public void setAuthenticated(boolean authenticated) {
        if (!this.usernamePasswordAuthenticationToken.isAuthenticated()) {
            Assert.notNull(this.usernamePasswordAuthenticationToken.getCredentials(), "Credentials were null for username password authentication token..");
            Assert.notNull(this.usernamePasswordAuthenticationToken.getAuthorities(), "Authorities were null of username password authentication token.");
            Assert.notNull(this.usernamePasswordAuthenticationToken.getPrincipal(), "Principal was null of username password authentication token.");
            this.usernamePasswordAuthenticationToken = new UsernamePasswordAuthenticationToken(this.usernamePasswordAuthenticationToken.getPrincipal(),
                    this.usernamePasswordAuthenticationToken.getCredentials(), this.usernamePasswordAuthenticationToken.getAuthorities());
        }
        if (!this.clientAuthentication.isAuthenticated()) {
            Assert.notNull(this.clientAuthentication.getRegisteredClient(), "Registered client was null.");
            Assert.notNull(this.clientAuthentication.getCredentials(), "Registered client was null.");
            this.clientAuthentication = new OAuth2ClientAuthenticationToken(this.clientAuthentication.getRegisteredClient(), this.clientAuthentication.getClientAuthenticationMethod(), this.clientAuthentication.getCredentials());
        }
    }

    @Override
    public void eraseCredentials() {
        this.usernamePasswordAuthenticationToken.eraseCredentials();
        this.clientAuthentication.eraseCredentials();
    }

    @Override
    public String getName() {
        return this.usernamePasswordAuthenticationToken.getName();
    }
}
