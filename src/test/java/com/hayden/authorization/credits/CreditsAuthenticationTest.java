package com.hayden.authorization.credits;

import com.unboundid.util.Base64;
import lombok.SneakyThrows;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.test.context.junit.jupiter.SpringExtension;
import org.springframework.test.web.servlet.MockMvc;

import static com.hayden.authorization.config.AuthorizationServerConfig.computeRedirectEndpoint;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.csrf;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultHandlers.print;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;

@SpringBootTest
@ExtendWith(SpringExtension.class)
@AutoConfigureMockMvc
public class CreditsAuthenticationTest {

    @Autowired
    MockMvc mockMvc;
    @Autowired
    JwtDecoder jwtDecoder;

    @SneakyThrows
    @Test
    public void testPaymentIncrement() {
        mockMvc.perform(
                        post("/api/v1/credits/increment")
                                .with(csrf())
                                .header("Content-Type", MediaType.APPLICATION_JSON_VALUE)
                                .header("Stripe-Signature", "hello!")
                                .content("""
                                        { "hello": "goodbye" }
                                        """)
                )
                .andExpect(status().is2xxSuccessful())
                .andDo(print());
        mockMvc.perform(
                       post("/oauth2/token")
                               .with(csrf())
                               .header("Content-Type", MediaType.APPLICATION_JSON_VALUE)
               )
               .andExpect(status().is3xxRedirection())
               .andExpect(redirectedUrl("http://localhost/login"))
               .andDo(print());
        mockMvc.perform(
                       post("/oauth2/token")
                               .with(csrf())
                               .header("Content-Type", MediaType.APPLICATION_JSON_VALUE)
                               .param("grant_type", AuthorizationGrantType.PASSWORD.getValue())
                               .param("client_id", "client")
                               .param("client_secret", "secret")
                               .header(HttpHeaders.AUTHORIZATION, "Basic %s".formatted(Base64.encode("whatever:hello!!!")))
               )
               .andExpect(redirectedUrl("http://localhost/login"))
               .andDo(print());
    }

    @Test
    public void testExpand() {
        var found = computeRedirectEndpoint("http://localhost", "code", "cdc-client", "{baseUrl}/{action}/oauth2/code/{registrationId}");
        System.out.println(found);
    }

}