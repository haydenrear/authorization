package com.hayden.authorization.oauth2;

import com.google.common.collect.Sets;
import com.hayden.authorization.user.CdcUser;
import com.hayden.authorization.user.CdcUserRepository;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
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
    public static final HashSet<String> AUTHORIZED_SCOPES = Sets.newHashSet("openid", "user", "user:email", "read:user", "profile", "address", "phone", "email");
    private final OAuth2AuthorizationService authorizationService;
    private final CdcUserRepository cdcUserRepository;
    private final RegisteredClientRepository registeredClientRepository;
    private final JwtEncoder jwtEncoder;

    @Override
    public void onAuthenticationSuccess(HttpServletRequest request, HttpServletResponse response, Authentication authentication) throws IOException, ServletException {

        if (authentication instanceof OAuth2AuthenticationToken auth
            && auth.getPrincipal() instanceof CdcUser user) {
//                                 create a jwt token from this oauth2 authentication token with our key
            var found = registeredClientRepository.findById("cdc");

            OAuth2TokenContext tokenContext = DefaultOAuth2TokenContext
                    .builder()
                    .registeredClient(found)
                    .principal(authentication)
                    .context(a -> a.putAll(user.getAttributes()))
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
                    .authorizedScopes(Sets.newHashSet(AUTHORIZED_SCOPES))
                    .tokenType(OAuth2TokenType.ACCESS_TOKEN)
                    .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
                    .authorizationGrant(auth)
                    .build();

            var generator = new JwtGenerator(jwtEncoder);
            generator.setJwtCustomizer(context -> user.getAttributes()
                                                      .entrySet()
                                                      .stream()
                                                      .filter(e -> Objects.nonNull(e.getValue()))
                                                      .forEach(keyValue -> context.getClaims()
                                                                                  .claim(keyValue.getKey(), keyValue.getValue())));

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

    private void handleAuthorizationCode(HttpServletResponse response, CdcUser user, String t, Jwt generated, OAuth2TokenContext tokenContext, RegisteredClient found) {
        try {
            user.setJwtToken(t);
            cdcUserRepository.save(user);
            OAuth2AccessToken accessToken = new OAuth2AccessToken(OAuth2AccessToken.TokenType.BEARER,
                    t,
                    generated.getIssuedAt(),
                    generated.getExpiresAt(),
                    tokenContext.getAuthorizedScopes());

            var idToken = new OidcIdToken(
                    accessToken.getTokenValue(),
                    accessToken.getIssuedAt(),
                    accessToken.getExpiresAt(),
                    Map.of("email", user.getEmail()));

            OAuth2Authorization.Builder authorizationBuilder = OAuth2Authorization
                    .withRegisteredClient(found)
                    .principalName(user.getName())
                    .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
                    .authorizedScopes(AUTHORIZED_SCOPES);

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
