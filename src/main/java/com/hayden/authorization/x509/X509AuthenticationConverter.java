package com.hayden.authorization.x509;

import com.hayden.authorization.auth_utils.ParameterUtils;
import com.hayden.authorization.client_credentials.ClientCredentialsParentExtractor;
import jakarta.servlet.http.HttpServletRequest;
import lombok.RequiredArgsConstructor;
import org.apache.commons.compress.utils.Lists;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2ClientAuthenticationToken;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.web.authentication.ClientSecretBasicAuthenticationConverter;
import org.springframework.security.oauth2.server.authorization.web.authentication.ClientSecretPostAuthenticationConverter;
import org.springframework.security.web.authentication.AuthenticationConverter;
import org.springframework.web.servlet.tags.Param;

import java.sql.ParameterMetaData;
import java.util.Map;
import java.util.Optional;

@RequiredArgsConstructor
public class X509AuthenticationConverter implements AuthenticationConverter {


    private final ClientCredentialsParentExtractor parentExtractor;

    @Override
    public Authentication convert(HttpServletRequest request) {
        if (ParameterUtils.isGrantType(request, X509AuthenticationGrantType.X_509)) {
            return X509AuthenticationGrantType.extractCert(request)
                    .flatMap(x -> Optional.ofNullable(parentExtractor.convert(request))
                            .map(o -> Map.entry(x, o))
                    )
                    .map(certExtracted -> new X509AuthenticationToken(Lists.newArrayList(), certExtracted.getValue(), certExtracted.getKey()))
                    .orElse(null);
        }

        return null;
    }


}
