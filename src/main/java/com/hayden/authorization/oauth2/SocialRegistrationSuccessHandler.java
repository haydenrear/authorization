package com.hayden.authorization.oauth2;

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
import org.springframework.security.oauth2.jwt.JwtEncoder;
import org.springframework.security.oauth2.server.authorization.OAuth2Authorization;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationService;
import org.springframework.security.oauth2.server.authorization.OAuth2TokenType;
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
import java.util.HashSet;
import java.util.Objects;
import java.util.Optional;

@Service
@RequiredArgsConstructor
@Slf4j
public class SocialRegistrationSuccessHandler implements AuthenticationSuccessHandler {
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

            OAuth2TokenContext tokenContext = DefaultOAuth2TokenContext.builder()
                                                                       .registeredClient(found)
                                                                       .principal(authentication)
                                                                       .context(a -> a.putAll(user.getAttributes()))
                                                                       .authorizationServerContext(new AuthorizationServerContext() {
                                                                           @Override
                                                                           public String getIssuer() {
                                                                               return "localhost:8080";
                                                                           }

                                                                           @Override
                                                                           public AuthorizationServerSettings getAuthorizationServerSettings() {
                                                                               return AuthorizationServerSettings.builder().build();
                                                                           }
                                                                       })
                                                                       .authorizedScopes(new HashSet<>())
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
                            t -> {
                                try {
                                    user.setJwtToken(t);
                                    cdcUserRepository.save(user);
                                    OAuth2AccessToken accessToken = new OAuth2AccessToken(OAuth2AccessToken.TokenType.BEARER,
                                            t,
                                            generated.getIssuedAt(),
                                            generated.getExpiresAt(), tokenContext.getAuthorizedScopes());

                                    OAuth2Authorization.Builder authorizationBuilder = OAuth2Authorization.withRegisteredClient(found)
                                                                                                          .principalName(user.getName())
                                                                                                          .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
                                                                                                          .authorizedScopes(new HashSet<>());

                                    authorizationBuilder.token(accessToken, (metadata) ->
                                            metadata.put(OAuth2Authorization.Token.CLAIMS_METADATA_NAME, generated.getClaims()));

                                    OAuth2Authorization authorization = authorizationBuilder.build();

                                    authorizationService.save(authorization);
                                    response.getWriter()
                                            .write("Authentication successful. Here is your API key: %s".formatted(t));
                                } catch (
                                        IOException e) {
                                    log.error("Error writing response: {}.", e.getMessage(), e);
                                }
                            },
                            () -> {
                                try {
                                    response.getWriter()
                                            .write("Authentication failure. No API key issued.");
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
}
