package com.hayden.authorization.stripe;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ObjectNode;
import com.hayden.authorization.user.CdcUser;
import com.hayden.authorization.user.CdcUserRepository;
import com.stripe.net.Webhook;
import lombok.SneakyThrows;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.http.MediaType;
import org.springframework.test.context.junit.jupiter.SpringExtension;
import org.springframework.test.web.servlet.MockMvc;

import java.io.InputStream;
import java.time.Instant;
import java.util.UUID;

import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.csrf;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultHandlers.print;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

/**
 * Integration tests for Stripe webhook processing through the CreditsController.
 * Tests various failure modes and success scenarios using actual Stripe event JSON files
 * with strategic modifications for different test scenarios.
 */
@SpringBootTest
@ExtendWith(SpringExtension.class)
@AutoConfigureMockMvc
public class StripeWebhookServiceIntegrationTest {

    @Autowired
    private MockMvc mockMvc;

    @Autowired
    private CdcUserRepository userRepository;

    @Autowired
    private ObjectMapper objectMapper;

    @Autowired
    private StripeConfigProps stripeConfigProps;

    @BeforeEach
    public void setupTest() {
        // Clear any previous test data
        userRepository.deleteAll();
    }

    @AfterEach
    public void tearDown() {
        userRepository.deleteAll();
    }

    /**
     * Loads a test event JSON file from the classpath
     */
    @SneakyThrows
    private String loadTestEventJson(String filename) {
        InputStream inputStream = getClass().getClassLoader()
                .getResourceAsStream("test-req/" + filename);
        if (inputStream == null) {
            throw new IllegalArgumentException("Test resource not found: test-req/" + filename);
        }
        return new String(inputStream.readAllBytes());
    }

    /**
     * Modifies a payment intent event JSON to replace the customer email
     */
    @SneakyThrows
    private String modifyPaymentIntentEmail(String eventJson, String newEmail) {
        JsonNode rootNode = objectMapper.readTree(eventJson);
        ObjectNode dataObject = (ObjectNode) rootNode.get("data").get("object");
        
        // Set receipt_email which is used as a fallback for customer email
        dataObject.put("receipt_email", newEmail);
        
        return objectMapper.writeValueAsString(rootNode);
    }

    /**
     * Modifies a payment intent event JSON to replace the amount received
     */
    @SneakyThrows
    private String modifyPaymentIntentAmount(String eventJson, long newAmount) {
        JsonNode rootNode = objectMapper.readTree(eventJson);
        ObjectNode dataObject = (ObjectNode) rootNode.get("data").get("object");
        
        dataObject.put("amount_received", newAmount);

        return objectMapper.writeValueAsString(rootNode);
    }

    @SneakyThrows
    private String modifyIdempotentId(String eventJson) {
        JsonNode rootNode = objectMapper.readTree(eventJson);
        ObjectNode dataObject = (ObjectNode) rootNode.get("request");

        dataObject.put("idempotency_key", UUID.randomUUID().toString());

        return objectMapper.writeValueAsString(rootNode);
    }

    /**
     * Modifies a payment intent event JSON to change the event type
     */
    @SneakyThrows
    private String modifyEventType(String eventJson, String newEventType) {
        JsonNode rootNode = objectMapper.readTree(eventJson);
        ((ObjectNode) rootNode).put("type", newEventType);
        
        return objectMapper.writeValueAsString(rootNode);
    }

    @SneakyThrows
    @Test
    public void testStripeWebhook_InvalidSignature() {
        String eventJson = loadTestEventJson("payment-intent-succeeded.json");

        mockMvc.perform(
                        post("/api/v1/credits/stripe/add-credits")
                                .with(csrf())
                                .header("Stripe-Signature", "invalid-signature-that-does-not-match")
                                .contentType(MediaType.APPLICATION_JSON)
                                .content(eventJson)
                )
                .andExpect(status().isUnauthorized())
                .andDo(print());
    }

    @SneakyThrows
    @Test
    public void testStripeWebhook_MalformedPayload() {
        String malformedPayload = "{ invalid json }";
        String webhookSecret = getWebhookSecret(malformedPayload);

        mockMvc.perform(
                        post("/api/v1/credits/stripe/add-credits")
                                .with(csrf())
                                .header("Stripe-Signature", webhookSecret)
                                .contentType(MediaType.APPLICATION_JSON)
                                .content(malformedPayload)
                )
                .andExpect(status().is5xxServerError())
                .andDo(print());
    }

    @SneakyThrows
    @Test
    public void testStripeWebhook_EmptyPayload() {
        String webhookSecret = getWebhookSecret("");

        mockMvc.perform(
                        post("/api/v1/credits/stripe/add-credits")
                                .with(csrf())
                                .header("Stripe-Signature", webhookSecret)
                                .contentType(MediaType.APPLICATION_JSON)
                                .content("")
                )
                .andExpect(status().isBadRequest())
                .andDo(print());
    }

    @SneakyThrows
    private String getWebhookSecret(String payload) {
        String webhookSecret = stripeConfigProps.getWebhookSecretToUse();
        long epochMilli = Instant.now().toEpochMilli();
        var toSign = String.format("%d.%s", epochMilli, payload);
        var computed = Webhook.Util.computeHmacSha256(webhookSecret, toSign);
        return "t=%s,v1=%s,v1=%s".formatted(epochMilli, webhookSecret, computed);
    }

    @SneakyThrows
    @Test
    public void testStripeWebhook_NullSignatureHeader() {
        String eventJson = loadTestEventJson("payment-intent-succeeded.json");

        mockMvc.perform(
                        post("/api/v1/credits/stripe/add-credits")
                                .with(csrf())
                                .contentType(MediaType.APPLICATION_JSON)
                                .content(eventJson)
                )
                .andExpect(status().isBadRequest())
                .andDo(print());
    }

    @SneakyThrows
    @Test
    public void testStripeWebhook_PaymentFailedEvent() {
        String eventJson = loadTestEventJson("payment-intent-succeeded.json");
        String modifiedJson = modifyEventType(eventJson, "payment_intent.payment_failed");
        String webhookSecret = getWebhookSecret(modifiedJson);

        mockMvc.perform(
                        post("/api/v1/credits/stripe/add-credits")
                                .with(csrf())
                                .header("Stripe-Signature", webhookSecret)
                                .contentType(MediaType.APPLICATION_JSON)
                                .content(modifiedJson)
                )
                .andExpect(status().isOk())
                .andDo(print());
    }

    @SneakyThrows
    @Test
    public void testStripeWebhook_PaymentCanceledEvent() {
        String eventJson = loadTestEventJson("payment-intent-succeeded.json");
        String modifiedJson = modifyEventType(eventJson, "payment_intent.canceled");
        String webhookSecret = getWebhookSecret(modifiedJson);

        mockMvc.perform(
                        post("/api/v1/credits/stripe/add-credits")
                                .with(csrf())
                                .header("Stripe-Signature", webhookSecret)
                                .contentType(MediaType.APPLICATION_JSON)
                                .content(modifiedJson)
                )
                .andExpect(status().isOk())
                .andDo(print());
    }

    @SneakyThrows
    @Test
    public void testStripeWebhook_UnknownEventType() {
        String eventJson = loadTestEventJson("payment-intent-succeeded.json");
        String modifiedJson = modifyEventType(eventJson, "payment_intent.unknown_event");
        String webhookSecret = getWebhookSecret(modifiedJson);

        mockMvc.perform(
                        post("/api/v1/credits/stripe/add-credits")
                                .with(csrf())
                                .header("Stripe-Signature", webhookSecret)
                                .contentType(MediaType.APPLICATION_JSON)
                                .content(modifiedJson)
                )
                .andExpect(status().isNotFound())
                .andDo(print());
    }

    @SneakyThrows
    @Test
    public void testStripeWebhook_UserNotFound() {
        String eventJson = loadTestEventJson("payment-intent-succeeded.json");
        String modifiedJson = modifyPaymentIntentEmail(eventJson, "unknown-user@example.com");
        String webhookSecret = getWebhookSecret(modifiedJson);

        mockMvc.perform(
                        post("/api/v1/credits/stripe/add-credits")
                                .with(csrf())
                                .header("Stripe-Signature", webhookSecret)
                                .contentType(MediaType.APPLICATION_JSON)
                                .content(modifiedJson)
                )
                .andExpect(status().isNotFound())
                .andDo(print());
    }

    @SneakyThrows
    @Test
    public void testStripeWebhook_SuccessfulPayment() {
        // Create a test user
        CdcUser.CdcUserId userId = new CdcUser.CdcUserId("stripe-user", "cdc");
        CdcUser user = CdcUser.builder()
                .principalId(userId)
                .email("stripe-customer@example.com")
                .password("test-password")
                .credits(new CdcUser.Credits(50, 0, Instant.now()))
                .build();
        userRepository.save(user);

        // Modify the event with our test user's email
        String eventJson = loadTestEventJson("payment-intent-succeeded.json");
        String modifiedJson = modifyPaymentIntentEmail(eventJson, "stripe-customer@example.com");
        String webhookSecret = getWebhookSecret(modifiedJson);

        mockMvc.perform(
                        post("/api/v1/credits/stripe/add-credits")
                                .with(csrf())
                                .header("Stripe-Signature", webhookSecret)
                                .contentType(MediaType.APPLICATION_JSON)
                                .content(modifiedJson)
                )
                .andExpect(status().isOk())
                .andDo(print());

        // Verify user's credits were incremented
        CdcUser updatedUser = userRepository.findById(userId).orElseThrow();
        // From payment-intent-succeeded.json: amount_received is 2000 cents ($20)
        int expectedCredits = 50 + (int) (2000 * stripeConfigProps.getCreditsPerCent());
        assert updatedUser.getCredits().current() == expectedCredits :
                "Expected " + expectedCredits + " credits, got " + updatedUser.getCredits().current();
    }

    @SneakyThrows
    @Test
    public void testStripeWebhook_ZeroAmount() {
        // Create a test user
        CdcUser.CdcUserId userId = new CdcUser.CdcUserId("zero-amount-user", "cdc");
        CdcUser user = CdcUser.builder()
                .principalId(userId)
                .email("zero-amount@example.com")
                .password("test-password")
                .credits(new CdcUser.Credits(100, 0, Instant.now()))
                .build();
        userRepository.save(user);

        // Modify the event with zero amount
        String eventJson = loadTestEventJson("payment-intent-succeeded.json");
        String modifiedJson = modifyPaymentIntentEmail(eventJson, "zero-amount@example.com");
        modifiedJson = modifyPaymentIntentAmount(modifiedJson, 0);
        String webhookSecret = getWebhookSecret(modifiedJson);

        mockMvc.perform(
                        post("/api/v1/credits/stripe/add-credits")
                                .with(csrf())
                                .header("Stripe-Signature", webhookSecret)
                                .contentType(MediaType.APPLICATION_JSON)
                                .content(modifiedJson)
                )
                .andExpect(status().isOk())
                .andDo(print());

        // Verify user's credits were not changed (0 credits added)
        CdcUser updatedUser = userRepository.findById(userId).orElseThrow();
        assert updatedUser.getCredits().current() == 100 :
                "Credits should remain 100, got " + updatedUser.getCredits().current();
    }

    @SneakyThrows
    @Test
    public void testStripeWebhook_MultiplePayments() {
        // Create a test user
        CdcUser.CdcUserId userId = new CdcUser.CdcUserId("multi-payment-user", "cdc");
        CdcUser user = CdcUser.builder()
                .principalId(userId)
                .email("multi-payment@example.com")
                .password("test-password")
                .credits(new CdcUser.Credits(100, 0, Instant.now()))
                .build();
        userRepository.save(user);

        int creditsPerCent = stripeConfigProps.getCreditsPerCent();

        // First payment: $50 (5000 cents)
        String eventJson = loadTestEventJson("payment-intent-succeeded.json");
        String modifiedJson = modifyPaymentIntentEmail(eventJson, "multi-payment@example.com");
        modifiedJson = modifyPaymentIntentAmount(modifiedJson, 5000);
        String webhookSecret = getWebhookSecret(modifiedJson);
        mockMvc.perform(
                        post("/api/v1/credits/stripe/add-credits")
                                .with(csrf())
                                .header("Stripe-Signature", webhookSecret)
                                .contentType(MediaType.APPLICATION_JSON)
                                .content(modifiedJson)
                )
                .andExpect(status().isOk())
                .andDo(print());

        CdcUser afterPayment1 = userRepository.findById(userId).orElseThrow();
        int expectedAfterPayment1 = 100 + (int) (5000 * creditsPerCent);
        assert afterPayment1.getCredits().current() == expectedAfterPayment1;

        // Second payment: $25 (2500 cents)
        eventJson = loadTestEventJson("payment-intent-succeeded.json");
        modifiedJson = modifyPaymentIntentEmail(eventJson, "multi-payment@example.com");
        modifiedJson = modifyPaymentIntentAmount(modifiedJson, 2500);
        webhookSecret = getWebhookSecret(modifiedJson);
        mockMvc.perform(
                        post("/api/v1/credits/stripe/add-credits")
                                .with(csrf())
                                .header("Stripe-Signature", webhookSecret)
                                .contentType(MediaType.APPLICATION_JSON)
                                .content(modifiedJson)
                )
                .andExpect(status().isOk())
                .andDo(print());

        CdcUser afterPayment2 = userRepository.findById(userId).orElseThrow();
//        didn't update idempotent id
        int expectedAfterPayment2 = expectedAfterPayment1 ;
        assert afterPayment2.getCredits().current() == expectedAfterPayment2;

        eventJson = loadTestEventJson("payment-intent-succeeded.json");
        modifiedJson = modifyPaymentIntentEmail(eventJson, "multi-payment@example.com");
        modifiedJson = modifyIdempotentId(modifiedJson);
        modifiedJson = modifyPaymentIntentAmount(modifiedJson, 2500);
        webhookSecret = getWebhookSecret(modifiedJson);

        mockMvc.perform(
                        post("/api/v1/credits/stripe/add-credits")
                                .with(csrf())
                                .header("Stripe-Signature", webhookSecret)
                                .contentType(MediaType.APPLICATION_JSON)
                                .content(modifiedJson)
                )
                .andExpect(status().isOk())
                .andDo(print());

        afterPayment2 = userRepository.findById(userId).orElseThrow();
        expectedAfterPayment2 = expectedAfterPayment1 + (2500 * creditsPerCent);
        assert afterPayment2.getCredits().current() == expectedAfterPayment2;
    }

    @SneakyThrows
    @Test
    public void testStripeWebhook_LargePaymentAmount() {
        // Create a test user
        CdcUser.CdcUserId userId = new CdcUser.CdcUserId("large-payment-user", "cdc");
        CdcUser user = CdcUser.builder()
                .principalId(userId)
                .email("large-payment@example.com")
                .password("test-password")
                .credits(new CdcUser.Credits(0, 0, Instant.now()))
                .build();
        userRepository.save(user);

        // Modify the event with a large amount ($10,000 = 1000000 cents)
        String eventJson = loadTestEventJson("payment-intent-succeeded.json");
        String modifiedJson = modifyPaymentIntentEmail(eventJson, "large-payment@example.com");
        modifiedJson = modifyPaymentIntentAmount(modifiedJson, 1000000);
        String webhookSecret = getWebhookSecret(modifiedJson);

        mockMvc.perform(
                        post("/api/v1/credits/stripe/add-credits")
                                .with(csrf())
                                .header("Stripe-Signature", webhookSecret)
                                .contentType(MediaType.APPLICATION_JSON)
                                .content(modifiedJson)
                )
                .andExpect(status().isOk())
                .andDo(print());

        // Verify user's credits were incremented significantly
        CdcUser updatedUser = userRepository.findById(userId).orElseThrow();
        int expectedCredits = (int) (1000000 * stripeConfigProps.getCreditsPerCent());
        assert updatedUser.getCredits().current() == expectedCredits :
                "Expected " + expectedCredits + " credits, got " + updatedUser.getCredits().current();
    }
}
