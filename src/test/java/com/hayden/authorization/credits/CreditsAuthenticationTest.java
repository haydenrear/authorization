package com.hayden.authorization.credits;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.hayden.authorization.user.CdcUser;
import com.hayden.authorization.user.CdcUserRepository;
import com.hayden.commitdiffmodel.credits.CreditsResponse;
import com.hayden.commitdiffmodel.credits.GetAndDecrementCreditsRequest;
import com.unboundid.util.Base64;
import lombok.SneakyThrows;
import org.hamcrest.Matchers;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.jose.jws.SignatureAlgorithm;
import org.springframework.security.oauth2.jwt.JwsHeader;
import org.springframework.security.oauth2.jwt.JwtClaimsSet;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.JwtEncoderParameters;
import org.springframework.security.oauth2.jwt.NimbusJwtEncoder;
import org.springframework.test.context.TestPropertySource;
import org.springframework.test.context.junit.jupiter.SpringExtension;
import org.springframework.test.web.servlet.MockMvc;

import java.time.Instant;
import java.time.temporal.ChronoUnit;

import static com.hayden.authorization.config.AuthorizationServerConfig.computeRedirectEndpoint;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.csrf;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.*;
import static org.springframework.test.web.servlet.result.MockMvcResultHandlers.print;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;

@SpringBootTest
@ExtendWith(SpringExtension.class)
@AutoConfigureMockMvc
@TestPropertySource(
        properties = {
                "stripe.webhook-secret="
        }
)
public class CreditsAuthenticationTest {

    @Autowired
    MockMvc mockMvc;
    @Autowired
    JwtDecoder jwtDecoder;
    @Autowired
    NimbusJwtEncoder jwtEncoder;
    @Autowired
    CdcUserRepository userRepository;
    @Autowired
    ObjectMapper objectMapper;

    private String accessToken;
    private CdcUser.CdcUserId testUserId;
    private CdcUser testUser;

    @BeforeEach
    public void setUp() {
        // Create a test user with initial credits
        testUserId = new CdcUser.CdcUserId("test-principal", "test-client");
        testUser = CdcUser.builder()
                .principalId(testUserId)
                .email("test@example.com")
                .password("test-password")
                .credits(new CdcUser.Credits(100, 0, Instant.now()))
                .build();
        userRepository.save(testUser);

        // Generate a valid JWT token for the test user
        accessToken = generateTestToken("test-principal", "test-client");
    }

    private String generateTestToken(String principalId, String clientId) {
        Instant now = Instant.now();
        JwtClaimsSet claims = JwtClaimsSet.builder()
                .issuer("self")
                .subject(principalId)
                .claim("client_id", clientId)
                .issuedAt(now)
                .expiresAt(now.plus(1, ChronoUnit.HOURS))
                .build();

        JwsHeader header = JwsHeader.with(SignatureAlgorithm.RS256)
                .type("JWT")
                .build();

        return jwtEncoder.encode(JwtEncoderParameters.from(header, claims)).getTokenValue();
    }

    @SneakyThrows
    @Test
    public void testGetCredits_Successful() {
        mockMvc.perform(
                        get("/api/v1/credits/get-credits")
                                .header("Authorization", "Bearer " + accessToken)
                                .contentType(MediaType.APPLICATION_JSON)
                )
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.hasCredits").value(true))
                .andExpect(jsonPath("$.remaining").value(100))
                .andExpect(jsonPath("$.userId").value("test-principal"))
                .andDo(print());
    }

    @SneakyThrows
    @Test
    public void testGetCredits_NoAuthentication() {
        mockMvc.perform(
                        get("/api/v1/credits/get-credits")
                                .contentType(MediaType.APPLICATION_JSON)
                )
                .andExpect(status().isUnauthorized())
                .andDo(print());
    }

    @SneakyThrows
    @Test
    public void testGetCredits_UserNotFound() {
        String unknownToken = generateTestToken("unknown-user", "unknown-client");
        
        mockMvc.perform(
                        get("/api/v1/credits/get-credits")
                                .header("Authorization", "Bearer " + unknownToken)
                                .contentType(MediaType.APPLICATION_JSON)
                )
                .andExpect(status().isNotFound())
                .andDo(print());
    }

    @SneakyThrows
    @Test
    public void testGetAndDecrement_Successful() {
        GetAndDecrementCreditsRequest request = GetAndDecrementCreditsRequest.builder()
                .amount(10)
                .build();

        mockMvc.perform(
                        post("/api/v1/credits/get-and-decrement")
                                .header("Authorization", "Bearer " + accessToken)
                                .contentType(MediaType.APPLICATION_JSON)
                                .content(objectMapper.writeValueAsString(request))
                )
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.hasCredits").value(true))
                .andExpect(jsonPath("$.remaining").value(90))
                .andExpect(jsonPath("$.consumed").value(10))
                .andExpect(jsonPath("$.userId").value("test-principal"))
                .andDo(print());

        // Verify the user's credits were actually decremented
        CdcUser updatedUser = userRepository.findById(testUserId).orElseThrow();
        assert updatedUser.getCredits().current() == 90;
    }

    @SneakyThrows
    @Test
    public void testGetAndDecrement_InsufficientCredits() {
        GetAndDecrementCreditsRequest request = GetAndDecrementCreditsRequest.builder()
                .amount(150)  // More than the 100 available
                .build();

        mockMvc.perform(
                        post("/api/v1/credits/get-and-decrement")
                                .header("Authorization", "Bearer " + accessToken)
                                .contentType(MediaType.APPLICATION_JSON)
                                .content(objectMapper.writeValueAsString(request))
                )
                .andExpect(status().isUnauthorized())
                .andExpect(jsonPath("$.hasCredits").value(false))
                .andExpect(jsonPath("$.reason").value("INSUFFICIENT_CREDITS"))
                .andDo(print());

        // Verify the user's credits were NOT decremented
        CdcUser updatedUser = userRepository.findById(testUserId).orElseThrow();
        assert updatedUser.getCredits().current() == 100;
    }

    @SneakyThrows
    @Test
    public void testGetAndDecrement_MultipleRequests() {
        // First request: decrement by 25
        GetAndDecrementCreditsRequest request1 = GetAndDecrementCreditsRequest.builder()
                .amount(25)
                .build();

        mockMvc.perform(
                        post("/api/v1/credits/get-and-decrement")
                                .header("Authorization", "Bearer " + accessToken)
                                .contentType(MediaType.APPLICATION_JSON)
                                .content(objectMapper.writeValueAsString(request1))
                )
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.remaining").value(75))
                .andDo(print());

        // Second request: decrement by 30
        GetAndDecrementCreditsRequest request2 = GetAndDecrementCreditsRequest.builder()
                .amount(30)
                .build();

        mockMvc.perform(
                        post("/api/v1/credits/get-and-decrement")
                                .header("Authorization", "Bearer " + accessToken)
                                .contentType(MediaType.APPLICATION_JSON)
                                .content(objectMapper.writeValueAsString(request2))
                )
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.remaining").value(45))
                .andDo(print());

        // Third request: decrement by 45 (all remaining)
        GetAndDecrementCreditsRequest request3 = GetAndDecrementCreditsRequest.builder()
                .amount(45)
                .build();

        mockMvc.perform(
                        post("/api/v1/credits/get-and-decrement")
                                .header("Authorization", "Bearer " + accessToken)
                                .contentType(MediaType.APPLICATION_JSON)
                                .content(objectMapper.writeValueAsString(request3))
                )
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.remaining").value(0))
                .andDo(print());

        // Fourth request: should fail
        GetAndDecrementCreditsRequest request4 = GetAndDecrementCreditsRequest.builder()
                .amount(1)
                .build();

        mockMvc.perform(
                        post("/api/v1/credits/get-and-decrement")
                                .header("Authorization", "Bearer " + accessToken)
                                .contentType(MediaType.APPLICATION_JSON)
                                .content(objectMapper.writeValueAsString(request4))
                )
                .andExpect(status().isUnauthorized())
                .andExpect(jsonPath("$.hasCredits").value(false))
                .andDo(print());
    }

    @SneakyThrows
    @Test
    public void testGetAndDecrement_NoAuthentication() {
        GetAndDecrementCreditsRequest request = GetAndDecrementCreditsRequest.builder()
                .amount(10)
                .build();

        mockMvc.perform(
                        post("/api/v1/credits/get-and-decrement")
                                .contentType(MediaType.APPLICATION_JSON)
                                .content(objectMapper.writeValueAsString(request))
                )
                .andExpect(status().is(Matchers.oneOf(403, 401)))
                .andDo(print());
    }

    @SneakyThrows
    @Test
    public void testStripeWebhook_InvalidSignature() {
        mockMvc.perform(
                        post("/api/v1/credits/stripe/add-credits")
                                .with(csrf())
                                .header("Stripe-Signature", "invalid-signature")
                                .contentType(MediaType.APPLICATION_JSON)
                                .content("{\"id\":\"evt_test\",\"type\":\"checkout.session.completed\"}")
                )
                .andExpect(status().isUnauthorized())
                .andDo(print());
    }

    @SneakyThrows
    @Test
    public void testStripeWebhook_NonPaymentEvent() {
        // This test demonstrates handling of non-payment events
        // In a real scenario, we'd need a valid signature to proceed
        mockMvc.perform(
                        post("/api/v1/credits/stripe/add-credits")
                                .with(csrf())
                                .header("Stripe-Signature", "invalid")
                                .contentType(MediaType.APPLICATION_JSON)
                                .content("{\"id\":\"evt_test\",\"type\":\"charge.failed\"}")
                )
                .andExpect(status().isUnauthorized())  // Due to invalid signature
                .andDo(print());
    }

    @SneakyThrows
    @Test
    public void testPaymentIncrement() {
        mockMvc.perform(
                        post("/api/v1/credits/stripe/add-credits")
                                .with(csrf())
                                .header("Content-Type", MediaType.APPLICATION_JSON_VALUE)
                                .header("Stripe-Signature", "hello!")
                                .content("""
                                        { "hello": "goodbye" }
                                        """)
                )
                .andExpect(status().is(401))
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
                               .param("client_id", "cdc-oauth2-client")
                               .param("client_secret", "234234lkjsldkdjfsd")
                               .header(HttpHeaders.AUTHORIZATION, "Basic %s".formatted(Base64.encode("whatever:hello!!!")))
               )
               .andExpect(redirectedUrl("http://localhost/login"))
               .andDo(print());
    }

    @SneakyThrows
    @Test
    public void testStripeWebhook_SuccessfulPayment() {
        // Create a test user with known email for Stripe webhook lookup
        CdcUser.CdcUserId stripeUserId = new CdcUser.CdcUserId("stripe-test-user", "stripe-test-client");
        CdcUser stripeUser = CdcUser.builder()
                .principalId(stripeUserId)
                .email("stripe-customer@example.com")
                .password("test-password")
                .credits(new CdcUser.Credits(50, 0, Instant.now()))
                .build();
        userRepository.save(stripeUser);

        // Build a mock Stripe checkout.session.completed event
        String stripeEventPayload = """
                {
                  "id": "evt_test123",
                  "type": "checkout.session.completed",
                  "created": 1234567890,
                  "api_version": "2023-10-16",
                  "data": {
                    "object": {
                      "id": "cs_test_session123",
                      "customer_email": "stripe-customer@example.com",
                      "amount_total": 5000,
                      "currency": "usd",
                      "status": "complete",
                      "payment_status": "paid",
                      "mode": "payment"
                    }
                  }
                }
                """;

        mockMvc.perform(
                        post("/api/v1/credits/stripe/add-credits")
                                .with(csrf())
                                .header("Stripe-Signature", "invalid-signature")
                                .contentType(MediaType.APPLICATION_JSON)
                                .content(stripeEventPayload)
                )
                .andExpect(status().isUnauthorized())  // Invalid signature
                .andDo(print());

        // Verify credits were NOT added (due to invalid signature)
        CdcUser userAfterInvalidWebhook = userRepository.findById(stripeUserId).orElseThrow();
        assert userAfterInvalidWebhook.getCredits().current() == 50 : "Credits should not change with invalid signature";
    }

    @SneakyThrows
    @Test
    public void testStripeWebhook_MissingCustomerEmail() {
        // Build a mock Stripe event without customer email
        String stripeEventPayload = """
                {
                  "id": "evt_test456",
                  "type": "checkout.session.completed",
                  "created": 1234567890,
                  "api_version": "2023-10-16",
                  "data": {
                    "object": {
                      "id": "cs_test_session456",
                      "amount_total": 5000,
                      "currency": "usd",
                      "status": "complete",
                      "payment_status": "paid",
                      "mode": "payment"
                    }
                  }
                }
                """;

        mockMvc.perform(
                        post("/api/v1/credits/stripe/add-credits")
                                .with(csrf())
                                .header("Stripe-Signature", "invalid-signature")
                                .contentType(MediaType.APPLICATION_JSON)
                                .content(stripeEventPayload)
                )
                .andExpect(status().isUnauthorized())
                .andDo(print());
    }

    @Test
    public void testExpand() {
        var found = computeRedirectEndpoint("http://localhost", "code", "cdc-client", "{baseUrl}/{action}/oauth2/code/{registrationId}");
        System.out.println(found);
    }

}
