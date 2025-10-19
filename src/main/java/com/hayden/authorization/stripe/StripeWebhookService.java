package com.hayden.authorization.stripe;

import com.hayden.commitdiffmodel.stripe.StripeCheckoutSession;
import com.hayden.commitdiffmodel.stripe.StripeWebhookEvent;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.stripe.model.Event;
import com.stripe.net.Webhook;
import io.micrometer.common.util.StringUtils;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;

import java.util.Objects;
import java.util.Optional;

/**
 * Service for validating and processing Stripe webhooks.
 * Handles webhook signature verification and event parsing.
 */
@Service
@RequiredArgsConstructor
@Slf4j
public class StripeWebhookService {

    private final StripeConfigProps stripeConfig;
    private final ObjectMapper objectMapper;

    /**
     * Validates the Stripe webhook signature and returns the parsed event if valid.
     *
     * @param payload    the raw request body
     * @param sigHeader  the Stripe-Signature header value
     * @return Optional containing the validated event, empty if signature is invalid
     */
    public Optional<StripeWebhookEvent> validateAndParseWebhook(String payload, String sigHeader) {
        try {
            String webhookSecret = stripeConfig.getWebhookSecretToUse();

            if (StringUtils.isBlank(webhookSecret)) {
                log.warn("Stripe webhook secret not configured");
                return Optional.empty();
            }

            Event event = Webhook.constructEvent(payload, sigHeader, webhookSecret);

            JsonNode eventJson = objectMapper.readTree(payload);
            StripeWebhookEvent webhookEvent = objectMapper.convertValue(eventJson, StripeWebhookEvent.class);
            
            log.info("Validated Stripe webhook event: {} (ID: {})", webhookEvent.getType(), webhookEvent.getId());
            return Optional.of(webhookEvent);
        } catch (com.stripe.exception.SignatureVerificationException e) {
            log.warn("Invalid Stripe webhook signature: {}", e.getMessage());
            return Optional.empty();
        } catch (Exception e) {
            log.error("Error processing Stripe webhook", e);
            return Optional.empty();
        }
    }

    /**
     * Extracts a checkout session from a webhook event.
     *
     * @param event the validated webhook event
     * @return Optional containing the checkout session if present in the event
     */
    public Optional<StripeCheckoutSession> extractCheckoutSession(StripeWebhookEvent event) {
        try {
            if (event.getData() == null || event.getData().getObject() == null) {
                return Optional.empty();
            }

            // The object is typically a checkout session for payment events
            JsonNode objectNode = objectMapper.valueToTree(event.getData().getObject());
            StripeCheckoutSession session = objectMapper.treeToValue(objectNode, StripeCheckoutSession.class);
            return Optional.of(session);
        } catch (Exception e) {
            log.error("Error extracting checkout session from webhook event", e);
            return Optional.empty();
        }
    }

    /**
     * Calculates the number of credits to add based on the amount paid.
     *
     * @param amountCents the amount in cents
     * @return number of credits to add
     */
    public int calculateCredits(long amountCents) {
        return (int) (amountCents * stripeConfig.getCreditsPerCent());
    }

    /**
     * Checks if a webhook event is a successful payment event.
     *
     * @param event the webhook event
     * @return true if this is a payment success event
     */
    public boolean isPaymentSuccessEvent(StripeWebhookEvent event) {
        // Common payment success events
        return "checkout.session.completed".equals(event.getType()) ||
               "payment_intent.succeeded".equals(event.getType());
    }
}
