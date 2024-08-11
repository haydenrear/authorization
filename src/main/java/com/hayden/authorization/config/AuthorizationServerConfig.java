package com.hayden.authorization.config;

import com.google.common.collect.Lists;
import com.hayden.authorization.client_credentials.ClientCredentialsParentExtractor;
import com.hayden.authorization.password.PasswordCredentialsAuthenticationProvider;
import com.hayden.authorization.password.PasswordCredentialsGrantAuthenticationConverter;
import com.hayden.authorization.web_authn.OAuth2WebAuthnAuthenticationConverter;
import com.hayden.authorization.web_authn.OAuth2WebAuthnAuthenticationProvider;
import com.hayden.authorization.x509.X509AuthenticationConverter;
import com.hayden.authorization.x509.X509AuthenticationGrantType;
import com.hayden.authorization.x509.OAuth2X509AuthenticationProvider;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.source.ImmutableJWKSet;
import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.proc.SecurityContext;
import com.webauthn4j.WebAuthnManager;
import com.webauthn4j.springframework.security.DefaultUserVerificationStrategy;
import com.webauthn4j.springframework.security.UserVerificationStrategy;
import com.webauthn4j.springframework.security.WebAuthnAuthenticationProvider;
import com.webauthn4j.springframework.security.WebAuthnProcessingFilter;
import com.webauthn4j.springframework.security.challenge.ChallengeRepository;
import com.webauthn4j.springframework.security.challenge.HttpSessionChallengeRepository;
import com.webauthn4j.springframework.security.credential.InMemoryWebAuthnCredentialRecordManager;
import com.webauthn4j.springframework.security.credential.WebAuthnCredentialRecordService;
import com.webauthn4j.springframework.security.server.ServerPropertyProvider;
import com.webauthn4j.springframework.security.server.ServerPropertyProviderImpl;
import org.springframework.beans.BeansException;
import org.springframework.beans.factory.config.BeanPostProcessor;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.http.MediaType;
import org.springframework.security.authentication.*;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.core.OAuth2Token;
import org.springframework.security.oauth2.core.oidc.OidcScopes;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.JwtEncoder;
import org.springframework.security.oauth2.jwt.NimbusJwtEncoder;
import org.springframework.security.oauth2.server.authorization.InMemoryOAuth2AuthorizationService;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationService;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2AuthorizationCodeRequestAuthenticationToken;
import org.springframework.security.oauth2.server.authorization.client.InMemoryRegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.config.annotation.web.configuration.OAuth2AuthorizationServerConfiguration;
import org.springframework.security.oauth2.server.authorization.config.annotation.web.configurers.OAuth2AuthorizationServerConfigurer;
import org.springframework.security.oauth2.server.authorization.settings.AuthorizationServerSettings;
import org.springframework.security.oauth2.server.authorization.settings.ClientSettings;
import org.springframework.security.oauth2.server.authorization.settings.OAuth2TokenFormat;
import org.springframework.security.oauth2.server.authorization.settings.TokenSettings;
import org.springframework.security.oauth2.server.authorization.token.JwtGenerator;
import org.springframework.security.oauth2.server.authorization.token.OAuth2TokenGenerator;
import org.springframework.security.oauth2.server.authorization.web.OAuth2ClientAuthenticationFilter;
import org.springframework.security.oauth2.server.authorization.web.OAuth2TokenEndpointFilter;
import org.springframework.security.oauth2.server.authorization.web.authentication.*;
import org.springframework.security.provisioning.UserDetailsManager;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.AuthenticationConverter;
import org.springframework.security.web.authentication.LoginUrlAuthenticationEntryPoint;
import org.springframework.security.web.util.matcher.MediaTypeRequestMatcher;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.util.ArrayList;
import java.util.UUID;

@Configuration
@EnableWebSecurity
public class AuthorizationServerConfig {

    @Bean
    @Order(1)
    SecurityFilterChain authorizationServerSecurityFilterChain(HttpSecurity http)
            throws Exception {
        OAuth2AuthorizationServerConfiguration.applyDefaultSecurity(http);
        http.getConfigurer(OAuth2AuthorizationServerConfigurer.class)
                .oidc(Customizer.withDefaults());	// Enable OpenID Connect 1.0
        http
                // Redirect to the login page when not authenticated from the
                // authorization endpoint
                .exceptionHandling((exceptions) -> exceptions
                        .defaultAuthenticationEntryPointFor(
                                new LoginUrlAuthenticationEntryPoint("/login"),
                                new MediaTypeRequestMatcher(MediaType.TEXT_HTML)
                        )
                )
                // Accept access tokens for User Info and/or Client Registration
                .oauth2ResourceServer((resourceServer) -> resourceServer
                        .jwt(Customizer.withDefaults()));

        return http.build();
    }

    @Bean
    @Order(2)
    SecurityFilterChain defaultSecurityFilterChain(HttpSecurity http)
            throws Exception {
        http
                .authorizeHttpRequests((authorize) -> authorize
                        .anyRequest().authenticated()
                )
                // Form login handles the redirect to the login page from the
                // authorization server filter chain
                .httpBasic(Customizer.withDefaults())
                .formLogin(Customizer.withDefaults());

        return http.build();
    }


    @Bean
    OAuth2AuthorizationService authorizationService() {
        return new InMemoryOAuth2AuthorizationService();
    }

    @Bean
    JwtEncoder jwtEncoder(JWKSource<SecurityContext> source) {
        return new NimbusJwtEncoder(source);
    }

    @Bean
    OAuth2TokenGenerator<? extends OAuth2Token> tokenGenerator(JwtEncoder jwtEncoder) {
        return new JwtGenerator(jwtEncoder);
    }

    @Bean
    BeanPostProcessor oAuth2ClientAuthenticationFilterProcessor(PasswordCredentialsAuthenticationProvider passwordCredentialsAuthenticationProvider,
                                                                OAuth2X509AuthenticationProvider x509AuthenticationProvider,
                                                                AuthenticationConverter authenticationConverterPassword,
                                                                OAuth2WebAuthnAuthenticationProvider oAuth2WebAuthnAuthenticationProvider) {
        return new BeanPostProcessor() {
            @Override
            public Object postProcessBeforeInitialization(Object bean, String beanName) throws BeansException {
                switch(bean) {
                    case OAuth2ClientAuthenticationFilter o -> o.setAuthenticationConverter(authenticationConverter());
                    case OAuth2TokenEndpointFilter oAuth2TokenEndpointFilter -> oAuth2TokenEndpointFilter.setAuthenticationConverter(authenticationConverterPassword);
                    case ProviderManager p -> {
                        addProviderAsFirst(p, passwordCredentialsAuthenticationProvider);
                        addProviderAsFirst(p, x509AuthenticationProvider);
                        addProviderAsFirst(p, oAuth2WebAuthnAuthenticationProvider);
                    }
                    default -> {}
                }
                return BeanPostProcessor.super.postProcessBeforeInitialization(bean, beanName);
            }
        };
    }

    @Bean
    WebAuthnAuthenticationProvider webAuthnAuthenticationProvider() {
        WebAuthnCredentialRecordService credentialRecordService = new InMemoryWebAuthnCredentialRecordManager();
        WebAuthnManager webAuthnManager = WebAuthnManager.createNonStrictWebAuthnManager();

        return new WebAuthnAuthenticationProvider(credentialRecordService, webAuthnManager);
    }

    @Bean
    AuthenticationManager webAuthnAuthenticationManager() {
        return new ProviderManager(webAuthnAuthenticationProvider());
    }

    /**
     * For extracting the client credentials
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
    HttpSessionChallengeRepository challengeRepository() {
        return new HttpSessionChallengeRepository();
    }

    @Bean
    ServerPropertyProvider serverPropertyProvider(ChallengeRepository challengeRepository) {
        return new ServerPropertyProviderImpl(challengeRepository);
    }

    @Bean
    UserVerificationStrategy userVerificationStrategy() {
        return new DefaultUserVerificationStrategy();
    }

    @Bean
    WebAuthnProcessingFilter webAuthnProcessingFilter(ServerPropertyProvider serverPropertyProvider,
                                                      UserVerificationStrategy userVerificationStrategy) {
        var w = new WebAuthnProcessingFilter(new ArrayList<>(), serverPropertyProvider, userVerificationStrategy);
        w.setAuthenticationManager(webAuthnAuthenticationManager());
        return w;
    }


    @Bean
    AuthenticationConverter authenticationConverterPassword(ClientCredentialsParentExtractor parentExtractor,
                                                            UserDetailsManager userDetailsManager,
                                                            OAuth2WebAuthnAuthenticationConverter webAuthnAuthenticationConverter) {
        return new DelegatingAuthenticationConverter(
                Lists.newArrayList(
                        new PasswordCredentialsGrantAuthenticationConverter(parentExtractor),
                        new X509AuthenticationConverter(parentExtractor, userDetailsManager),
                        webAuthnAuthenticationConverter,
                        new OAuth2AuthorizationCodeAuthenticationConverter(),
                        new OAuth2DeviceCodeAuthenticationConverter(),
                        new OAuth2RefreshTokenAuthenticationConverter(),
                        new OAuth2ClientCredentialsAuthenticationConverter()
                )
        );
    }

    @Bean
    RegisteredClientRepository registeredClientRepository() {
        RegisteredClient oidcClient = RegisteredClient.withId(UUID.randomUUID().toString())
                .clientId("client")
                .clientSecret("{noop}secret")
                .clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_POST)
                // used with the token jwkSetUrl
//                .clientAuthenticationMethod(ClientAuthenticationMethod.PRIVATE_KEY_JWT)
                .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
                .authorizationGrantType(AuthorizationGrantType.PASSWORD)
                .authorizationGrantType(AuthorizationGrantType.REFRESH_TOKEN)
                .authorizationGrantType(AuthorizationGrantType.DEVICE_CODE)
                .authorizationGrantType(AuthorizationGrantType.CLIENT_CREDENTIALS)
                .authorizationGrantType(X509AuthenticationGrantType.X_509)
                .redirectUri("http://127.0.0.1:8080/login/oauth2/code/oidc-client")
                .postLogoutRedirectUri("http://127.0.0.1:8080/")
                .scope(OidcScopes.OPENID)
                .scope(OidcScopes.PROFILE)
                .tokenSettings(TokenSettings.builder()
                        .accessTokenFormat(OAuth2TokenFormat.SELF_CONTAINED)
                        .build()
                )
                .clientSettings(ClientSettings.builder()
                        .requireAuthorizationConsent(true)
//                        .tokenEndpointAuthenticationSigningAlgorithm(SignatureAlgorithm.ES256)
                        // validates the client's jwt assertion
//                        .jwkSetUrl("...")
                        .build()
                )
                .build();

        return new InMemoryRegisteredClientRepository(oidcClient);
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

    @Bean
    JwtDecoder jwtDecoder(JWKSource<SecurityContext> jwkSource) {
        return OAuth2AuthorizationServerConfiguration.jwtDecoder(jwkSource);
    }

    @Bean
    AuthorizationServerSettings authorizationServerSettings() {
        return AuthorizationServerSettings.builder().build();
    }


    private static KeyPair generateRsaKey() {
        KeyPair keyPair;
        try {
            KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
            keyPairGenerator.initialize(2048);
            keyPair = keyPairGenerator.generateKeyPair();
        }
        catch (Exception ex) {
            throw new IllegalStateException(ex);
        }
        return keyPair;
    }

    private static void addProviderAsFirst(ProviderManager p,
                                           AuthenticationProvider provider) {
        if (p.getProviders().stream().anyMatch(a -> a.supports(OAuth2AuthorizationCodeRequestAuthenticationToken.class))) {
            p.getProviders().addFirst(provider);
        }
    }


}
