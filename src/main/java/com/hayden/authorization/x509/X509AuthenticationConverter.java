package com.hayden.authorization.x509;

import com.hayden.authorization.auth_utils.ParameterUtils;
import com.hayden.authorization.client_credentials.ClientCredentialsParentExtractor;
import jakarta.servlet.http.HttpServletRequest;
import lombok.RequiredArgsConstructor;
import org.apache.commons.compress.utils.Lists;
import org.jetbrains.annotations.NotNull;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2ClientAuthenticationToken;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.web.authentication.ClientSecretBasicAuthenticationConverter;
import org.springframework.security.oauth2.server.authorization.web.authentication.ClientSecretPostAuthenticationConverter;
import org.springframework.security.provisioning.UserDetailsManager;
import org.springframework.security.web.authentication.AuthenticationConverter;
import org.springframework.web.servlet.tags.Param;

import java.security.cert.X509Certificate;
import java.sql.ParameterMetaData;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Map;
import java.util.Optional;

@RequiredArgsConstructor
public class X509AuthenticationConverter implements AuthenticationConverter {


    private final ClientCredentialsParentExtractor parentExtractor;
    private final UserDetailsManager userDetailsManager;

    @Override
    public Authentication convert(HttpServletRequest request) {
        if (ParameterUtils.isGrantType(request, X509AuthenticationGrantType.X_509)) {
            return X509AuthenticationGrantType.extractCert(request)
                    .flatMap(x -> Optional.ofNullable(parentExtractor.convert(request))
                            .map(o -> Map.entry(x, o))
                    )
                    .map(certExtracted -> new X509AuthenticationToken(
                            loadCreateUser(certExtracted),
                            certExtracted.getValue(),
                            certExtracted.getKey())
                    )
                    .orElse(null);
        }

        return null;
    }

    private @NotNull Collection<? extends GrantedAuthority> loadCreateUser(Map.Entry<X509Certificate, OAuth2ClientAuthenticationToken> certExtracted) {
        return Optional.ofNullable(userDetailsManager.loadUserByUsername(certExtracted.getKey().getIssuerX500Principal().getName()))
                .or(() -> {
                    // TODO extract roles from cert?
                    UserDetails build = User.withUsername(certExtracted.getKey().getIssuerX500Principal().getName()).build();
                    userDetailsManager.createUser(build);
                    return Optional.of(build);
                })
                .map(UserDetails::getAuthorities)
                .orElse(new ArrayList<>());
    }


}
