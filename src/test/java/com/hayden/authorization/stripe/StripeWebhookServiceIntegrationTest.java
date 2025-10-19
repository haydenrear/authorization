package com.hayden.authorization.stripe;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.google.gson.*;
import com.hayden.authorization.user.CdcUser;
import com.hayden.authorization.user.CdcUserRepository;
import com.stripe.Stripe;
import com.stripe.model.*;
import com.stripe.model.Address;
import com.stripe.model.Customer;
import com.stripe.model.PaymentIntent;
import com.stripe.net.Webhook;
import lombok.SneakyThrows;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.context.annotation.Profile;
import org.springframework.http.MediaType;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.context.junit.jupiter.SpringExtension;
import org.springframework.test.web.servlet.MockMvc;

import java.time.Instant;

import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.csrf;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultHandlers.print;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

/**
 * Integration tests for Stripe webhook processing through the CreditsController.
 * Tests various failure modes and success scenarios using actual Stripe data models
 * serialized with Jackson, ensuring compatibility with Stripe SDK updates.
 */
@SpringBootTest
@ExtendWith(SpringExtension.class)
@AutoConfigureMockMvc
@ActiveProfiles("test")
public class StripeWebhookServiceIntegrationTest {

    @Autowired
    private MockMvc mockMvc;

    @Autowired
    private CdcUserRepository userRepository;

    @Autowired
    private ObjectMapper objectMapper;

    @Autowired
    private StripeConfigProps stripeConfigProps;
    private static GsonBuilder builder =
            new GsonBuilder()
                    .setFieldNamingPolicy(FieldNamingPolicy.LOWER_CASE_WITH_UNDERSCORES)
                    .registerTypeAdapter(EphemeralKey.class, new EphemeralKeyDeserializer())
                    .registerTypeAdapter(Event.Data.class, new EventDataDeserializer())
                    .registerTypeAdapter(Event.Request.class, new EventRequestDeserializer())
                    .registerTypeAdapter(ExpandableField.class, new ExpandableFieldDeserializer())
                    .registerTypeAdapter(StripeRawJsonObject.class, new StripeRawJsonObjectDeserializer())
                    .addReflectionAccessFilter(
                            new ReflectionAccessFilter() {
                                @Override
                                public ReflectionAccessFilter.FilterResult check(Class<?> rawClass) {
                                    if (rawClass.getTypeName().startsWith("com.stripe.")) {
                                        return ReflectionAccessFilter.FilterResult.ALLOW;
                                    }
                                    return ReflectionAccessFilter.FilterResult.BLOCK_ALL;
                                }
                            });


    private static final Gson GSON = builder.create();


    @SneakyThrows
    @Test
    public void testStripeWebhook_InvalidSignature() {
        // Test with invalid signature header
        Event event = buildPaymentIntentEvent("payment_intent.succeeded", "test@example.com", 5000);
        String payload = getEventJson(event);

        mockMvc.perform(
                        post("/api/v1/credits/stripe/add-credits")
                                .with(csrf())
                                .header("Stripe-Signature", "invalid-signature-that-does-not-match")
                                .contentType(MediaType.APPLICATION_JSON)
                                .content(payload)
                )
                .andExpect(status().isUnauthorized())
                .andDo(print());
    }

    private String getEventJson(Event event) {
        String payload = GSON.toJson(event);
        return payload;
    }

    @SneakyThrows
    @Test
    public void testStripeWebhook_MalformedPayload() {
        // Test with malformed JSON payload
        String malformedPayload = "{ invalid json }";
        String webhookSecret = getWebhookSecret(malformedPayload);

        mockMvc.perform(
                        post("/api/v1/credits/stripe/add-credits")
                                .with(csrf())
                                .header("Stripe-Signature", webhookSecret)
                                .contentType(MediaType.APPLICATION_JSON)
                                .content(malformedPayload)
                )
                .andExpect(status().isUnauthorized())
                .andDo(print());
    }

    @SneakyThrows
    @Test
    public void testStripeWebhook_EmptyPayload() {
        // Test with empty payload
        String webhookSecret = getWebhookSecret("");

        mockMvc.perform(
                        post("/api/v1/credits/stripe/add-credits")
                                .with(csrf())
                                .header("Stripe-Signature", webhookSecret)
                                .contentType(MediaType.APPLICATION_JSON)
                                .content("")
                )
                .andExpect(status().isUnauthorized())
                .andDo(print());
    }

    @SneakyThrows
    @Test
    public void testStripeWebhook_NullSignatureHeader() {
        // Test with null/missing signature header
        Event event = buildPaymentIntentEvent("payment_intent.succeeded", "test@example.com", 5000);
        String payload = getEventJson(event);

        mockMvc.perform(
                        post("/api/v1/credits/stripe/add-credits")
                                .with(csrf())
                                .contentType(MediaType.APPLICATION_JSON)
                                .content(payload)
                )
                .andExpect(status().isUnauthorized())
                .andDo(print());
    }

    @SneakyThrows
    @Test
    public void testStripeWebhook_PaymentFailedEvent() {
        // Test with payment_intent.payment_failed event
        Event event = buildPaymentIntentEvent("payment_intent.payment_failed", "failed@example.com", 5000);
        String payload = getEventJson(event);
        String webhookSecret = getWebhookSecret(payload);

        mockMvc.perform(
                        post("/api/v1/credits/stripe/add-credits")
                                .with(csrf())
                                .header("Stripe-Signature", webhookSecret)
                                .contentType(MediaType.APPLICATION_JSON)
                                .content(payload)
                )
                .andExpect(status().isUnauthorized())
                .andDo(print());
    }

    @SneakyThrows
    @Test
    public void testStripeWebhook_PaymentCanceledEvent() {
        // Test with payment_intent.canceled event
        Event event = buildPaymentIntentEvent("payment_intent.canceled", "canceled@example.com", 5000);
        String payload = getEventJson(event);
        String webhookSecret = getWebhookSecret(payload);

        mockMvc.perform(
                        post("/api/v1/credits/stripe/add-credits")
                                .with(csrf())
                                .header("Stripe-Signature", webhookSecret)
                                .contentType(MediaType.APPLICATION_JSON)
                                .content(payload)
                )
                .andExpect(status().isUnauthorized())
                .andDo(print());
    }

    @SneakyThrows
    @Test
    public void testStripeWebhook_UnknownEventType() {
        // Test with unknown event type
        Event event = buildPaymentIntentEvent("payment_intent.unknown_event", "unknown@example.com", 5000);
        String payload = getEventJson(event);
        String webhookSecret = getWebhookSecret(payload);

        mockMvc.perform(
                        post("/api/v1/credits/stripe/add-credits")
                                .with(csrf())
                                .header("Stripe-Signature", webhookSecret)
                                .contentType(MediaType.APPLICATION_JSON)
                                .content(payload)
                )
                .andExpect(status().isUnauthorized())
                .andDo(print());
    }

    @SneakyThrows
    @Test
    public void testStripeWebhook_UserNotFound() {
        // Test when user is not found in the system
        Event event = buildPaymentIntentEvent("payment_intent.succeeded", "unknown-user@example.com", 5000);
        String payload = getEventJson(event);
        String webhookSecret = getWebhookSecret(payload);

        mockMvc.perform(
                        post("/api/v1/credits/stripe/add-credits")
                                .with(csrf())
                                .header("Stripe-Signature", webhookSecret)
                                .contentType(MediaType.APPLICATION_JSON)
                                .content(payload)
                )
                .andExpect(status().isNotFound())
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
    public void testStripeWebhook_SuccessfulPayment() {
        // Create a test user
        CdcUser.CdcUserId userId = new CdcUser.CdcUserId("stripe-user", "stripe-client");
        CdcUser user = CdcUser.builder()
                .principalId(userId)
                .email("stripe-customer@example.com")
                .password("test-password")
                .credits(new CdcUser.Credits(50, 0, Instant.now()))
                .build();
        userRepository.save(user);

        // Build a successful payment intent event
        Event event = buildPaymentIntentEvent("payment_intent.succeeded", "stripe-customer@example.com", 10000);
        String payload = getEventJson(event);
        String webhookSecret = getWebhookSecret(payload);

        mockMvc.perform(
                        post("/api/v1/credits/stripe/add-credits")
                                .with(csrf())
                                .header("Stripe-Signature", webhookSecret)
                                .contentType(MediaType.APPLICATION_JSON)
                                .content(payload)
                )
                .andExpect(status().isOk())
                .andDo(print());

        // Verify user's credits were incremented
        CdcUser updatedUser = userRepository.findById(userId).orElseThrow();
        int expectedCredits = 50 + (int) (10000 * stripeConfigProps.getCreditsPerCent());
        assert updatedUser.getCredits().current() == expectedCredits :
                "Expected " + expectedCredits + " credits, got " + updatedUser.getCredits().current();
    }

    @SneakyThrows
    @Test
    public void testStripeWebhook_ZeroAmount() {
        // Create a test user
        CdcUser.CdcUserId userId = new CdcUser.CdcUserId("zero-amount-user", "stripe-client");
        CdcUser user = CdcUser.builder()
                .principalId(userId)
                .email("zero-amount@example.com")
                .password("test-password")
                .credits(new CdcUser.Credits(100, 0, Instant.now()))
                .build();
        userRepository.save(user);

        // Build a payment intent with zero amount
        Event event = buildPaymentIntentEvent("payment_intent.succeeded", "zero-amount@example.com", 0);
        String payload = getEventJson(event);
        String webhookSecret = getWebhookSecret(payload);

        mockMvc.perform(
                        post("/api/v1/credits/stripe/add-credits")
                                .with(csrf())
                                .header("Stripe-Signature", webhookSecret)
                                .contentType(MediaType.APPLICATION_JSON)
                                .content(payload)
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
        CdcUser.CdcUserId userId = new CdcUser.CdcUserId("multi-payment-user", "stripe-client");
        CdcUser user = CdcUser.builder()
                .principalId(userId)
                .email("multi-payment@example.com")
                .password("test-password")
                .credits(new CdcUser.Credits(100, 0, Instant.now()))
                .build();
        userRepository.save(user);

        int creditsPerCent = stripeConfigProps.getCreditsPerCent();

        // First payment: $50
        Event event1 = buildPaymentIntentEvent("payment_intent.succeeded", "multi-payment@example.com", 5000);
        String payload1 = getEventJson(event1);
        String webhookSecret = getWebhookSecret(payload1);
        mockMvc.perform(
                        post("/api/v1/credits/stripe/add-credits")
                                .with(csrf())
                                .header("Stripe-Signature", webhookSecret)
                                .contentType(MediaType.APPLICATION_JSON)
                                .content(payload1)
                )
                .andExpect(status().isOk())
                .andDo(print());

        CdcUser afterPayment1 = userRepository.findById(userId).orElseThrow();
        int expectedAfterPayment1 = 100 + (int) (5000 * creditsPerCent);
        assert afterPayment1.getCredits().current() == expectedAfterPayment1;

        // Second payment: $25
        Event event2 = buildPaymentIntentEvent("payment_intent.succeeded", "multi-payment@example.com", 2500);
        String payload2 = getEventJson(event2);
        mockMvc.perform(
                        post("/api/v1/credits/stripe/add-credits")
                                .with(csrf())
                                .header("Stripe-Signature", webhookSecret)
                                .contentType(MediaType.APPLICATION_JSON)
                                .content(payload2)
                )
                .andExpect(status().isOk())
                .andDo(print());

        CdcUser afterPayment2 = userRepository.findById(userId).orElseThrow();
        int expectedAfterPayment2 = expectedAfterPayment1 + (int) (2500 * creditsPerCent);
        assert afterPayment2.getCredits().current() == expectedAfterPayment2;
    }

    @SneakyThrows
    @Test
    public void testStripeWebhook_LargePaymentAmount() {
        // Create a test user
        CdcUser.CdcUserId userId = new CdcUser.CdcUserId("large-payment-user", "stripe-client");
        CdcUser user = CdcUser.builder()
                .principalId(userId)
                .email("large-payment@example.com")
                .password("test-password")
                .credits(new CdcUser.Credits(0, 0, Instant.now()))
                .build();
        userRepository.save(user);

        // Build a large payment intent ($10,000)
        Event event = buildPaymentIntentEvent("payment_intent.succeeded", "large-payment@example.com", 1000000);
        String payload = getEventJson(event);
        String webhookSecret = getWebhookSecret(payload);

        mockMvc.perform(
                        post("/api/v1/credits/stripe/add-credits")
                                .with(csrf())
                                .header("Stripe-Signature", webhookSecret)
                                .contentType(MediaType.APPLICATION_JSON)
                                .content(payload)
                )
                .andExpect(status().isOk())
                .andDo(print());

        // Verify user's credits were incremented significantly
        CdcUser updatedUser = userRepository.findById(userId).orElseThrow();
        int expectedCredits = (int) (1000000 * stripeConfigProps.getCreditsPerCent());
        assert updatedUser.getCredits().current() == expectedCredits :
                "Expected " + expectedCredits + " credits, got " + updatedUser.getCredits().current();
    }

    // Helper method to build a Stripe Payment Intent Event using actual Stripe data models
    private Event buildPaymentIntentEvent(String eventType, String customerEmail, long amountReceived) {
        Event event = new Event();
        event.setId("evt_test_" + System.nanoTime());
        event.setType(eventType);
        event.setCreated(System.currentTimeMillis() / 1000);
        event.setApiVersion(Stripe.API_VERSION);

        // Build Customer object
        com.stripe.model.Customer customer = new Customer();
        customer.setId("cus_test_" + customerEmail.hashCode());
        customer.setObject("customer");
        customer.setEmail(customerEmail);
        customer.setName(customerEmail.split("@")[0]);
        customer.setPhone("+1-555-0100");


        // Build Address object
        Address address = new com.stripe.model.Address();
        address.setCity("San Francisco");
        address.setCountry("US");
        address.setLine1("123 Main St");
        address.setPostalCode("94107");
        address.setState("CA");

        customer.setAddress(address);

        // Build PaymentIntent object
        PaymentIntent paymentIntent = new com.stripe.model.PaymentIntent();
        paymentIntent.setId("pi_test_" + System.nanoTime());
        paymentIntent.setObject("payment_intent");
        paymentIntent.setAmountReceived(amountReceived);
        paymentIntent.setCustomerObject(customer);

        // Set the payment intent as the event data
        JsonObject asJsonObject = GSON.toJsonTree(paymentIntent).getAsJsonObject();

        Event.Data eventData = new Event.Data();
        eventData.setObject(asJsonObject);
        event.setData(eventData);
        event.setApiVersion(Stripe.API_VERSION);

        return event;
    }

}
