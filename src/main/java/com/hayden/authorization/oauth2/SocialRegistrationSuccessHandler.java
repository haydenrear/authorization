package com.hayden.authorization.oauth2;

import com.google.common.collect.Sets;
import com.hayden.authorization.config.AuthorizationServerConfigProps;
import com.hayden.authorization.user.CdcUser;
import com.hayden.authorization.user.CdcUserRepository;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.jetbrains.annotations.NotNull;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.client.authentication.OAuth2AuthenticationToken;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.OAuth2AccessToken;
import org.springframework.security.oauth2.core.oidc.OidcIdToken;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtEncoder;
import org.springframework.security.oauth2.server.authorization.OAuth2Authorization;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationService;
import org.springframework.security.oauth2.server.authorization.OAuth2TokenType;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.context.AuthorizationServerContext;
import org.springframework.security.oauth2.server.authorization.settings.AuthorizationServerSettings;
import org.springframework.security.oauth2.server.authorization.token.DefaultOAuth2TokenContext;
import org.springframework.security.oauth2.server.authorization.token.JwtGenerator;
import org.springframework.security.oauth2.server.authorization.token.OAuth2TokenContext;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.stereotype.Service;

import java.io.IOException;
import java.io.Serial;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.*;

@Service
@RequiredArgsConstructor
@Slf4j
public class SocialRegistrationSuccessHandler implements AuthenticationSuccessHandler {
    private final AuthorizationServerConfigProps configProps;
    private final OAuth2AuthorizationService authorizationService;
    private final CdcUserRepository cdcUserRepository;
    private final RegisteredClientRepository registeredClientRepository;
    private final JwtEncoder jwtEncoder;

    @Override
    public void onAuthenticationSuccess(HttpServletRequest request, HttpServletResponse response, Authentication authentication) throws IOException, ServletException {

        if (authentication instanceof OAuth2AuthenticationToken auth
            && auth.getPrincipal() instanceof CdcUser user) {
            var found = registeredClientRepository.findById("cdc");

            OAuth2TokenContext tokenContext = DefaultOAuth2TokenContext
                    .builder()
                    .registeredClient(found)
                    .principal(authentication)
                    .context(a -> a.putAll(user.getOAuth2TokenContext()))
                    .authorizationServerContext(new AuthorizationServerContext() {
                        @Override
                        public String getIssuer() {
                            return getAuthorizationServerSettings().getIssuer();
                        }

                        @Override
                        public AuthorizationServerSettings getAuthorizationServerSettings() {
                            return AuthorizationServerSettings.builder()
                                    .build();
                        }
                    })
                    .authorizedScopes(Sets.newHashSet(configProps.getAuthorizedScopes()))
                    .tokenType(OAuth2TokenType.ACCESS_TOKEN)
                    .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
                    .authorizationGrant(auth)
                    .build();

            var generator = getJwtGenerator(user);

            var generated = generator.generate(tokenContext);

            Optional.ofNullable(generated)
                    .flatMap(j -> Optional.ofNullable(j.getTokenValue()))
                    .ifPresentOrElse(
                            t -> handleAuthorizationCode(response, user, t, generated, tokenContext, found),
                            () -> {
                                try {
                                    response.sendRedirect("/");
                                } catch (
                                        IOException e) {
                                    log.error("Error writing response: {}.", e.getMessage(), e);
                                }
                            });

        } else {
            response.getWriter()
                    .write("Authentication failed.");
        }
    }

    private @NotNull JwtGenerator getJwtGenerator(CdcUser user) {
        var generator = new JwtGenerator(jwtEncoder);

        generator.setJwtCustomizer(context -> user.getAttributes()
                                                  .entrySet()
                                                  .stream()
                                                  .filter(e -> Objects.nonNull(e.getValue()))
                                                  .forEach(keyValue -> context.getClaims()
                                                                              .claim(keyValue.getKey(), keyValue.getValue())));
        return generator;
    }

    private void handleAuthorizationCode(HttpServletResponse response, CdcUser user, String jwtToken, Jwt generated,
                                         OAuth2TokenContext tokenContext, RegisteredClient found) {
        try {
            user.setJwtToken(jwtToken);
            cdcUserRepository.save(user);
            OAuth2AccessToken accessToken = new OAuth2AccessToken(OAuth2AccessToken.TokenType.BEARER,
                    jwtToken,
                    generated.getIssuedAt(),
                    generated.getExpiresAt(),
                    tokenContext.getAuthorizedScopes());

            Map<String, Object> claims = user.getClaims();

            var idToken = new OidcIdToken(
                    accessToken.getTokenValue(),
                    accessToken.getIssuedAt(),
                    accessToken.getExpiresAt(),
                    claims);

            OAuth2Authorization.Builder authorizationBuilder = OAuth2Authorization
                    .withRegisteredClient(found)
                    .principalName(user.getPrincipalName())
                    .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
                    .authorizedScopes(new HashSet<>(configProps.getAuthorizedScopes()));

            authorizationBuilder.token(idToken,
                    (metadata) -> metadata.put(OAuth2Authorization.Token.CLAIMS_METADATA_NAME, idToken.getClaims()));

            authorizationBuilder.token(accessToken, (metadata) ->
                    metadata.put(OAuth2Authorization.Token.CLAIMS_METADATA_NAME, generated.getClaims()));

            OAuth2Authorization authorization = authorizationBuilder.build();

            authorizationService.save(authorization);
            response.sendRedirect("/?token=%s".formatted(generated.getTokenValue()));
        } catch (
                IOException e) {
            log.error("Error writing response: {}.", e.getMessage(), e);
        }
    }
}
