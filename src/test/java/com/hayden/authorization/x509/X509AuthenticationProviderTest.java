package com.hayden.authorization.x509;

import lombok.SneakyThrows;
import org.hamcrest.BaseMatcher;
import org.hamcrest.Description;
import org.hamcrest.Matchers;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.Mockito;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.http.MediaType;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.context.junit.jupiter.SpringExtension;
import org.springframework.test.web.servlet.MockMvc;

import javax.security.auth.x500.X500Principal;
import java.security.cert.X509Certificate;
import java.util.stream.Stream;

import static com.hayden.authorization.x509.X509AuthenticationGrantType.X_509_ATTRIBUTE;
import static org.junit.jupiter.api.Assertions.*;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.csrf;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultHandlers.print;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@SpringBootTest
@ExtendWith(SpringExtension.class)
@AutoConfigureMockMvc
@ActiveProfiles("test-auth")
public class X509AuthenticationProviderTest {


    @Autowired
    MockMvc mockMvc;
    @Autowired
    JwtDecoder jwtDecoder;

    @Mock
    X509Certificate x509Certificate;
    @Mock
    X500Principal principal;

    @SneakyThrows
    @Test
    public void doTestX509() {
        Mockito.when(principal.getName()).thenReturn("user");
        Mockito.when(x509Certificate.getIssuerX500Principal()).thenReturn(principal);

        mockMvc.perform(
                        post("/oauth2/token")
                                .with(csrf())
                                .header("Content-Type", MediaType.APPLICATION_JSON_VALUE)
                                .param("grant_type", X509AuthenticationGrantType.X_509.getValue())
                                .param("client_id", "client")
                                .param("client_secret", "secret")
                                .requestAttr(X_509_ATTRIBUTE, new X509Certificate[]{x509Certificate})
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