package com.hayden.authorization.config;

import com.google.common.collect.Lists;
import com.hayden.authorization.client_credentials.ClientCredentialsParentExtractor;
import com.hayden.authorization.oauth2.SocialRegistrationSuccessHandler;
import com.hayden.authorization.oidc.UserEndpointUserInfoMapper;
import com.hayden.authorization.password.PasswordCredentialsAuthenticationProvider;
import com.hayden.authorization.password.PasswordCredentialsGrantAuthenticationConverter;
import com.hayden.commitdiffmodel.config.DisableGraphQl;
import com.hayden.utilitymodule.security.KeyConfigProperties;
import com.hayden.utilitymodule.security.KeyFiles;
import com.hayden.authorization.x509.X509AuthenticationConverter;
import com.hayden.authorization.x509.X509AuthenticationGrantType;
import com.hayden.authorization.x509.OAuth2X509AuthenticationProvider;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.source.ImmutableJWKSet;
import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.proc.SecurityContext;
import jakarta.ws.rs.HttpMethod;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.BeansException;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.config.BeanPostProcessor;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Import;
import org.springframework.core.annotation.Order;
import org.springframework.http.MediaType;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.security.authentication.*;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.CsrfConfigurer;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.client.JdbcOAuth2AuthorizedClientService;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClientService;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository;
import org.springframework.security.oauth2.client.registration.InMemoryClientRegistrationRepository;
import org.springframework.security.oauth2.client.web.AuthenticatedPrincipalOAuth2AuthorizedClientRepository;
import org.springframework.security.oauth2.client.web.OAuth2AuthorizedClientRepository;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.OAuth2Token;
import org.springframework.security.oauth2.core.oidc.OidcScopes;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.JwtEncoder;
import org.springframework.security.oauth2.jwt.NimbusJwtEncoder;
import org.springframework.security.oauth2.server.authorization.JdbcOAuth2AuthorizationService;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationService;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2AuthorizationCodeRequestAuthenticationToken;
import org.springframework.security.oauth2.server.authorization.client.InMemoryRegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.config.annotation.web.configuration.OAuth2AuthorizationServerConfiguration;
import org.springframework.security.oauth2.server.authorization.config.annotation.web.configurers.OAuth2AuthorizationServerConfigurer;
import org.springframework.security.oauth2.server.authorization.oidc.authentication.OidcUserInfoAuthenticationProvider;
import org.springframework.security.oauth2.server.authorization.oidc.web.OidcUserInfoEndpointFilter;
import org.springframework.security.oauth2.server.authorization.settings.AuthorizationServerSettings;
import org.springframework.security.oauth2.server.authorization.settings.ClientSettings;
import org.springframework.security.oauth2.server.authorization.settings.OAuth2TokenFormat;
import org.springframework.security.oauth2.server.authorization.settings.TokenSettings;
import org.springframework.security.oauth2.server.authorization.token.*;
import org.springframework.security.oauth2.server.authorization.web.OAuth2ClientAuthenticationFilter;
import org.springframework.security.oauth2.server.authorization.web.OAuth2TokenEndpointFilter;
import org.springframework.security.oauth2.server.authorization.web.authentication.*;
import org.springframework.security.provisioning.UserDetailsManager;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.AuthenticationConverter;
import org.springframework.security.web.authentication.LoginUrlAuthenticationEntryPoint;
import org.springframework.security.web.util.matcher.MediaTypeRequestMatcher;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.util.UriComponents;
import org.springframework.web.util.UriComponentsBuilder;

import java.security.*;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.util.*;

@Slf4j
@Configuration
@EnableWebSecurity
@Import({KeyConfigProperties.class, KeyFiles.class, DisableGraphQl.class})
public class AuthorizationServerConfig {

    @Autowired
    private KeyFiles keyFiles;

    @Bean
    @Order(1)
    SecurityFilterChain authorizationServerSecurityFilterChain(HttpSecurity http)
            throws Exception {
        OAuth2AuthorizationServerConfiguration.applyDefaultSecurity(http);
        http.getConfigurer(OAuth2AuthorizationServerConfigurer.class)
            .oidc(Customizer.withDefaults());
//        TODO: this should have the login screen and other should have the oauth2 endpoint
        http
                .exceptionHandling((exceptions) -> exceptions
                        .defaultAuthenticationEntryPointFor(
                                new LoginUrlAuthenticationEntryPoint("/login"),
                                new MediaTypeRequestMatcher(MediaType.TEXT_HTML))
                )
                .oauth2ResourceServer((resourceServer) -> resourceServer.jwt(Customizer.withDefaults()));

        return http.build();
    }

    @Bean
    OidcUserInfoAuthenticationProvider oidcUserInfoAuthenticationProvider(OAuth2AuthorizationService authorizationService,
                                                                          UserEndpointUserInfoMapper mapper) {
        OidcUserInfoAuthenticationProvider provider = new OidcUserInfoAuthenticationProvider(authorizationService);
        provider.setUserInfoMapper(mapper);
        return provider;
    }


    @Bean
    @Order(2)
    SecurityFilterChain defaultSecurityFilterChain(HttpSecurity http,
                                                   OAuth2AuthorizedClientService authorizationClientService,
                                                   OAuth2AuthorizedClientRepository authorizedClientRepository,
                                                   SocialRegistrationSuccessHandler socialRegistrationSuccessHandler,
                                                   OidcUserInfoAuthenticationProvider provider)
            throws Exception {
        http
                .with(
                        OAuth2AuthorizationServerConfigurer.authorizationServer(),
                        auth -> {
                            auth.oidc(oidcConfigurer -> oidcConfigurer
                                    .userInfoEndpoint(userInfo -> {
                                        userInfo.authenticationProvider(provider);
                                    }));
                        })
                .authorizeHttpRequests((authorize) -> authorize
                        .requestMatchers("/api/v1/credits/stripe/**")
                        .permitAll()
                        .anyRequest()
                        .authenticated()
                )
                .oauth2ResourceServer((resourceServer) -> resourceServer.jwt(Customizer.withDefaults()))
                .oauth2Login(login -> login.successHandler(socialRegistrationSuccessHandler)
                                       .authorizedClientService(authorizationClientService)
                                       .authorizedClientRepository(authorizedClientRepository))
                .httpBasic(Customizer.withDefaults())
                .csrf(CsrfConfigurer::disable)
                .formLogin(Customizer.withDefaults());

        return http.build();
    }

    @Bean
    OAuth2AuthorizedClientService authorizedClientService(JdbcTemplate jdbcTemplate, ClientRegistrationRepository clientRegistrationRepository) {
        return new JdbcOAuth2AuthorizedClientService(jdbcTemplate, clientRegistrationRepository);
    }

    @Bean
    OAuth2AuthorizedClientRepository authorizedClientRepository(OAuth2AuthorizedClientService authorizedClientService) {
        return new AuthenticatedPrincipalOAuth2AuthorizedClientRepository(authorizedClientService);
    }

    @Bean
    OAuth2AuthorizationService authorizationService(JdbcTemplate jdbcTemplate, RegisteredClientRepository registeredClientRepository) {
        return new JdbcOAuth2AuthorizationService(jdbcTemplate, registeredClientRepository);
    }

    @Bean
    JwtEncoder jwtEncoder(JWKSource<SecurityContext> source) {
        return new NimbusJwtEncoder(source);
    }

    @Bean
    OAuth2TokenGenerator<? extends OAuth2Token> tokenGenerator(JwtEncoder jwtEncoder) {
        var j = new JwtGenerator(jwtEncoder);
        return j;
    }


    @Bean
    BeanPostProcessor oAuth2ClientAuthenticationFilterProcessor(PasswordCredentialsAuthenticationProvider passwordCredentialsAuthenticationProvider,
                                                                OAuth2X509AuthenticationProvider x509AuthenticationProvider,
                                                                AuthenticationConverter authenticationConverterPassword,
                                                                OidcUserInfoAuthenticationProvider authenticationProvider) {
        return new BeanPostProcessor() {
            @Override
            public Object postProcessBeforeInitialization(Object bean, String beanName) throws BeansException {
                switch (bean) {
                    case OAuth2ClientAuthenticationFilter o ->
                            o.setAuthenticationConverter(authenticationConverter());
                    case OAuth2TokenEndpointFilter oAuth2TokenEndpointFilter -> {
                            oAuth2TokenEndpointFilter.setAuthenticationConverter(authenticationConverterPassword);
                    }
                    case ProviderManager p -> {
                        addProviderAsFirst(p, passwordCredentialsAuthenticationProvider);
                        addProviderAsFirst(p, x509AuthenticationProvider);

                        p.getProviders().removeIf(aut -> aut.getClass().equals(OidcUserInfoAuthenticationProvider.class));
                        p.getProviders().add(authenticationProvider);
                    }
                    default -> {
                    }
                }
                return BeanPostProcessor.super.postProcessBeforeInitialization(bean, beanName);
            }
        };
    }

    /**
     * For extracting the client credentials
     *
     * @return
     */
    @Bean
    AuthenticationConverter parentDelegatingAuthenticationConverter() {
        return new DelegatingAuthenticationConverter(
                Lists.newArrayList(
                        new ClientSecretPostAuthenticationConverter(),
                        new JwtClientAssertionAuthenticationConverter(),
                        new PublicClientAuthenticationConverter()
                )
        );
    }


    @Bean
    AuthenticationConverter authenticationConverter() {
        return new DelegatingAuthenticationConverter(
                Lists.newArrayList(
                        new ClientSecretPostAuthenticationConverter(),
                        new JwtClientAssertionAuthenticationConverter(),
                        new PublicClientAuthenticationConverter()
                )
        );
    }


    @Bean
    AuthenticationConverter authenticationConverterPassword(ClientCredentialsParentExtractor parentExtractor,
                                                            UserDetailsManager userDetailsManager) {
        return new DelegatingAuthenticationConverter(
                Lists.newArrayList(
                        new PasswordCredentialsGrantAuthenticationConverter(parentExtractor),
                        new X509AuthenticationConverter(parentExtractor, userDetailsManager),
                        new OAuth2AuthorizationCodeAuthenticationConverter(),
                        new OAuth2DeviceCodeAuthenticationConverter(),
                        new OAuth2RefreshTokenAuthenticationConverter(),
                        new OAuth2ClientCredentialsAuthenticationConverter()
                )
        );
    }

    public static RegisteredClient toRegisteredClient(ClientRegistration clientRegistration,
                                                      PasswordEncoder passwordEncoder) {
        RegisteredClient.Builder r;
        if (Objects.equals(clientRegistration.getClientId(), "cdc-oauth2-client")) {
            r = RegisteredClient.withId(clientRegistration.getRegistrationId())
                                .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
                                .authorizationGrantType(AuthorizationGrantType.PASSWORD)
                                .authorizationGrantType(AuthorizationGrantType.REFRESH_TOKEN)
                                .authorizationGrantType(AuthorizationGrantType.DEVICE_CODE)
                                .authorizationGrantType(AuthorizationGrantType.CLIENT_CREDENTIALS)
                                .authorizationGrantType(X509AuthenticationGrantType.X_509);
        } else {
            r = RegisteredClient.withId(clientRegistration.getRegistrationId())
                    .authorizationGrantType(clientRegistration.getAuthorizationGrantType());
        }

        return r.clientId(clientRegistration.getClientId())
                .clientSecret(passwordEncoder.encode(clientRegistration.getClientSecret()))
                .clientAuthenticationMethod(clientRegistration.getClientAuthenticationMethod())
                // used with the token jwkSetUrl
//                .clientAuthenticationMethod(ClientAuthenticationMethod.PRIVATE_KEY_JWT)
                .redirectUri(computeRedirectEndpoint("http://localhost:8080","login", clientRegistration.getRegistrationId(), clientRegistration.getRedirectUri()))
                .postLogoutRedirectUri("http://127.0.0.1:8080/")
                .scope(OidcScopes.OPENID)
                .scope(OidcScopes.PROFILE)
                .tokenSettings(TokenSettings.builder()
                                            .accessTokenFormat(OAuth2TokenFormat.SELF_CONTAINED)
                                            .build()
                )
                .clientSettings(ClientSettings.builder()
                                              .requireAuthorizationConsent(true)
//                                            .tokenEndpointAuthenticationSigningAlgorithm(SignatureAlgorithm.ES256)
                                                                  // validates the client's jwt assertion
//                                            .jwkSetUrl("...")
                                              .build()
                )
                .build();
    }

    public static String computeRedirectEndpoint(String baseUrl, String action, String registrationId, String uri) {
        UriComponents uriComponents = UriComponentsBuilder.fromUriString(uri)
                                                          .build();

        Map<String, String> uriVariables = new HashMap<>();
        uriVariables.put("baseUrl", baseUrl);

        String path = uriComponents.getPath();
        uriVariables.put("action", action);

        uriVariables.put("registrationId", registrationId);

        return uriComponents.expand(uriVariables)
                            .toUriString();
    }

    @Bean
    RegisteredClientRepository registeredClientRepository(ClientRegistrationRepository clientRegistrationRepository,
                                                          PasswordEncoder passwordEncoder) {
        if (clientRegistrationRepository instanceof InMemoryClientRegistrationRepository mem) {
            var found = Lists.newArrayList(mem.iterator())
                    .stream()
                    .map(s -> toRegisteredClient(s, passwordEncoder))
                    .toList();
            return new InMemoryRegisteredClientRepository(found);
        }

        throw new RuntimeException("Could not find valid.");
    }

    @Bean
    JWKSource<SecurityContext> jwkSource() {
        KeyPair keyPair = generateRsaKey();
        RSAPublicKey publicKey = (RSAPublicKey) keyPair.getPublic();
        RSAPrivateKey privateKey = (RSAPrivateKey) keyPair.getPrivate();
        RSAKey rsaKey = new RSAKey.Builder(publicKey)
                .privateKey(privateKey)
                .keyID(UUID.randomUUID().toString())
                .build();
        JWKSet jwkSet = new JWKSet(rsaKey);
        return new ImmutableJWKSet<>(jwkSet);
    }

    KeyPair generateRsaKey() {
        return keyFiles.getKeyPair();
    }

    @Bean
    JwtDecoder jwtDecoder(JWKSource<SecurityContext> jwkSource) {
        return OAuth2AuthorizationServerConfiguration.jwtDecoder(jwkSource);
    }

    @Bean
    AuthorizationServerSettings authorizationServerSettings() {
        return AuthorizationServerSettings.builder()
                                          .build();
    }


    private static void addProviderAsFirst(ProviderManager p,
                                           AuthenticationProvider provider) {
        if (p.getProviders().stream()
             .anyMatch(a -> a.supports(OAuth2AuthorizationCodeRequestAuthenticationToken.class))) {
            p.getProviders().addFirst(provider);
        }
    }


}
