package com.hayden.authorization.password;

import com.unboundid.util.Base64;
import lombok.SneakyThrows;
import org.hamcrest.BaseMatcher;
import org.hamcrest.Description;
import org.hamcrest.Matchers;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository;
import org.springframework.security.oauth2.client.registration.InMemoryClientRegistrationRepository;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.context.junit.jupiter.SpringExtension;
import org.springframework.test.web.servlet.MockMvc;

import java.util.stream.Stream;

import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.csrf;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultHandlers.print;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;

@SpringBootTest
@ExtendWith(SpringExtension.class)
@AutoConfigureMockMvc
@ActiveProfiles("test-auth")
public class PasswordCredentialsAuthenticationProviderTest {

    @Autowired
    MockMvc mockMvc;
    @Autowired
    JwtDecoder jwtDecoder;
    @Autowired
    ClientRegistrationRepository clientRegistrationRepository;

    @SneakyThrows
    @Test
    public void doTestPasswordCreds() {

        mockMvc.perform(
                        post("/oauth2/token")
                                .with(csrf())
                                .header("Content-Type", MediaType.APPLICATION_JSON_VALUE)
                                .param("grant_type", AuthorizationGrantType.PASSWORD.getValue())
                                .param("client_id", "client")
                                .param("client_secret", "secret")
                                .header(HttpHeaders.AUTHORIZATION, "Basic %s".formatted(Base64.encode("user:password")))
                )
                .andExpect(status().is2xxSuccessful())
                .andExpect(jsonPath("$.access_token", Matchers.notNullValue()))
                .andExpect(jsonPath("$.access_token", Matchers.is(new BaseMatcher<String>() {
                    @Override
                    public boolean matches(Object o) {
                        var decoded = Assertions.assertDoesNotThrow(() -> jwtDecoder.decode(o.toString()));
                        var decodedScopes = Assertions.assertDoesNotThrow(() -> decoded.getClaimAsStringList("scope"));
                        return Stream.of("ROLE_USER", "openid", "profile")
                                .allMatch(decodedScopes::contains);
                    }

                    @Override
                    public void describeMismatch(Object o, Description description) {
                        description.appendText("%s not contain scopes!".formatted(o.toString()));
                    }

                    @Override
                    public void describeTo(Description description) {
                        description.appendText("Did not contain scopes!");
                    }
                })))
                .andDo(print());
    }

}