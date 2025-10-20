package com.hayden.authorization.authorization_code;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.github.tomakehurst.wiremock.WireMockServer;
import lombok.SneakyThrows;
import org.hamcrest.Matchers;
import org.intellij.lang.annotations.Language;
import org.jetbrains.annotations.NotNull;
import org.junit.jupiter.api.*;
import org.junit.jupiter.api.extension.ExtendWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.http.HttpHeaders;
import org.springframework.mock.web.MockHttpSession;
import org.springframework.security.oauth2.core.endpoint.OAuth2AuthorizationRequest;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.context.junit.jupiter.SpringExtension;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.MvcResult;
import org.springframework.web.util.UriComponentsBuilder;

import java.util.UUID;
import java.util.concurrent.atomic.AtomicReference;
import java.util.stream.Stream;

import static com.github.tomakehurst.wiremock.client.WireMock.*;
import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.csrf;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultHandlers.print;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;

@SpringBootTest
@ExtendWith(SpringExtension.class)
@AutoConfigureMockMvc
@ActiveProfiles({"test-auth", "test"})
public class GithubAuthorizationCodeAuthenticationProviderTest {

    @Autowired
    MockMvc mockMvc;
    @Autowired
    JwtDecoder jwtDecoder;
    @Autowired
    RegisteredClientRepository clientRegistrationRepository;

    private static final WireMockServer wireMockServer = new WireMockServer(8081);

    @Autowired
    private ObjectMapper objectMapper;

    @SneakyThrows
    @BeforeAll
    public static void performSetup() {
        wireMockServer.start();
        configureFor("localhost", 8081);
        stubFor(com.github.tomakehurst.wiremock.client.WireMock.post(urlPathEqualTo("/login/oauth/access_token"))
                .willReturn(aResponse()
                        .withHeader("Content-Type", "application/json")
                        .withBody("{\"access_token\":\"%s\",\"token_type\":\"Bearer\",\"expires_in\":3600}".formatted("hello"))));
        @Language("json") String body = """
                            {"login":"haydenrear","id":44076747,"node_id":"MDQ6VXNlcjQ0MDc2NzQ3","avatar_url":"https://avatars.githubusercontent.com/u/44076747?v=4","gravatar_id":"","url":"https://api.github.com/users/haydenrear","html_url":"https://github.com/haydenrear","followers_url":"https://api.github.com/users/haydenrear/followers","following_url":"https://api.github.com/users/haydenrear/following{/other_user}","gists_url":"https://api.github.com/users/haydenrear/gists{/gist_id}","starred_url":"https://api.github.com/users/haydenrear/starred{/owner}{/repo}","subscriptions_url":"https://api.github.com/users/haydenrear/subscriptions","organizations_url":"https://api.github.com/users/haydenrear/orgs","repos_url":"https://api.github.com/users/haydenrear/repos","events_url":"https://api.github.com/users/haydenrear/events{/privacy}","received_events_url":"https://api.github.com/users/haydenrear/received_events","type":"User","user_view_type":"private","site_admin":false,"name":"Hayden Rear","company":null,"blog":"","location":"Eugene, Oregon","email":null,"hireable":true,"bio":"hello","twitter_username":null,"notification_email":null,"public_repos":76,"public_gists":0,"followers":8,"following":17,"created_at":"2018-10-12T01:31:06Z","updated_at":"2025-10-13T17:19:28Z","private_gists":1,"total_private_repos":41,"owned_private_repos":41,"disk_usage":231839,"collaborators":2,"two_factor_authentication":true,"plan":{"name":"free","space":976562499,"collaborators":0,"private_repos":10000}}
                """;
        stubFor(com.github.tomakehurst.wiremock.client.WireMock.get(urlPathEqualTo("/userinfo"))
                .willReturn(aResponse()
                        .withHeader("Content-Type", "application/json")
                        .withBody(body)));
    }

    @AfterAll
    public static void after() {
        wireMockServer.stop();
    }


    @SneakyThrows
    @Test
    public void doTestGithubAuthorizationCodeFlow() {
        String githubClientId = "Ov23li6AX6ixxIAZ8llp";
        var found = this.clientRegistrationRepository.findByClientId(githubClientId);
        assertThat(found).isNotNull();

        AtomicReference<String> jwtToken = new AtomicReference<>();

        var authorize = mockMvc.perform(
                        get("/oauth2/authorization/github")
                                .with(csrf())
                )
                .andExpect(status().is3xxRedirection())
                .andReturn();

        assertThat(authorize.getRequest().getSession()).isNotNull();
        assertThat(authorize.getRequest().getSession()).isInstanceOf(MockHttpSession.class);
        MockHttpSession session = (MockHttpSession) authorize.getRequest().getSession();

        String oauth2AuthorizationState = getOAuth2AuthorizationState(session);
        var result = mockMvc.perform(
                        get("/login/oauth2/code/github")
                                .with(csrf())
                                .param("code", UUID.randomUUID().toString())
                                .param("state", oauth2AuthorizationState)
                                .param("client_id", githubClientId)
                                .session(session)
                )
                .andDo(print())
                .andExpect(status().is3xxRedirection())
                .andExpect(redirectedUrlPattern("/?token=*"))
                .andReturn();

        var token = extractToken(result, jwtToken);
        Assertions.assertNotNull(token, "JWT should not be null");

        var decoded = Assertions.assertDoesNotThrow(() -> jwtDecoder.decode(token));
        Assertions.assertNotNull(decoded, "Decoded JWT should not be null");
        
        var decodedScopes = decoded.getClaimAsStringList("scope");
        Assertions.assertNotNull(decodedScopes, "Scopes should not be null");
        Assertions.assertTrue(
                Stream.of("openid", "profile", "email")
                        .allMatch(decodedScopes::contains),
                "JWT should contain openid, profile, and email scopes");
        
        // Step 3: Use the JWT token to make an authenticated request
        mockMvc.perform(
                get("/api/v1/credits/get-credits")
                        .with(csrf())
                        .header(HttpHeaders.AUTHORIZATION, "Bearer %s".formatted(jwtToken.get()))
        )
        .andExpect(status().is2xxSuccessful())
        .andExpect(jsonPath("$", Matchers.notNullValue()))
        .andDo(print());

        mockMvc.perform(
                        get("/userinfo")
                                .with(csrf())
                                .param("client_id", githubClientId)
                                .param("client_secret", found.getClientSecret())
                                .header(HttpHeaders.AUTHORIZATION, "Bearer %s".formatted(jwtToken.get()))
                )
                .andExpect(status().is2xxSuccessful())
                .andExpect(jsonPath("$", Matchers.notNullValue()))
                .andDo(print());
    }

    private static @NotNull String getOAuth2AuthorizationState(MockHttpSession session) {
        // Step 2: GitHub redirects back with the authorization code
        assertThat(session).isNotNull();
        Object authRequest = session.getAttribute("org.springframework.security.oauth2.client.web.HttpSessionOAuth2AuthorizationRequestRepository.AUTHORIZATION_REQUEST");
        assertThat(authRequest).isNotNull();
        assertThat(authRequest).isInstanceOf(OAuth2AuthorizationRequest.class);
        String oauth2AuthorizationState = ((OAuth2AuthorizationRequest) authRequest).getState();
        assertThat(oauth2AuthorizationState).isNotNull();
        return oauth2AuthorizationState;
    }

    private static @NotNull String extractToken(MvcResult result, AtomicReference<String> jwtToken) {
        // Extract JWT token from redirect URL
        String tokenRedirectUrl = result.getResponse().getRedirectedUrl();
        assertThat(tokenRedirectUrl).isNotNull();
        var token = UriComponentsBuilder.fromUriString(tokenRedirectUrl)
                .build().getQueryParams().get("token")
                .getFirst();
        token = token.replaceAll("%.*$", "");
        jwtToken.set(token);
        return token;
    }

}