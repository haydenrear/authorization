package com.hayden.authorization.stripe;

import com.stripe.exception.SignatureVerificationException;
import com.stripe.model.PaymentIntent;
import com.hayden.commitdiffmodel.stripe.PaymentData;
import com.stripe.model.Event;
import com.stripe.model.EventDataObjectDeserializer;
import com.stripe.net.Webhook;
import io.micrometer.common.util.StringUtils;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.modelmapper.ModelMapper;
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
    private final ModelMapper modelMapper;

    /**
     * Validates the Stripe webhook signature and returns the parsed event if valid.
     *
     * @param payload    the raw request body
     * @param sigHeader  the Stripe-Signature header value
     * @return Optional containing the validated event, empty if signature is invalid
     */
    public PaymentData validateAndParseWebhook(String payload, String sigHeader) {
        try {
            String webhookSecret = stripeConfig.getWebhookSecretToUse();

            if (StringUtils.isBlank(webhookSecret)) {
                String secretNotConfigured = "Stripe webhook secret not configured";
                log.warn(secretNotConfigured);
                return PaymentData.builder()
                        .success(false)
                        .errorMessage(secretNotConfigured)
                        .build();
            }

            if (!Objects.equals(sigHeader, webhookSecret)) {
                return PaymentData.builder()
                        .success(false)
                        .errorMessage("Webhook secret did not match.")
                        .build();
            }

            Event event = Webhook.constructEvent(payload, sigHeader, webhookSecret);

            return Optional.ofNullable(event)
                    .flatMap(evt -> Optional.ofNullable(evt.getDataObjectDeserializer()))
                            .flatMap(EventDataObjectDeserializer::getObject)
                    .map(so -> switch(so) {
                        case PaymentIntent pi -> {
                            var pd = PaymentData.builder()
                                    .idempotentId(pi.getId())
                                    .sessionData(
                                            PaymentData.SessionData
                                                    .builder()
                                                    .name(pi.getCustomerObject().getName())
                                                    .email(pi.getCustomerObject().getEmail())
                                                    .ph(pi.getCustomerObject().getPhone())
                                                    .address(modelMapper.map(pi.getCustomerObject().getAddress(), PaymentData.Address.class))
                                                    .build()
                                    )
                                    .amountPaid(pi.getAmountReceived())
                                    .errorMessage("Payment was cancelled");
                            yield switch(event.getType()) {
                                case "payment_intent.payment_failed"  -> {
                                    yield pd.success(false)
                                            .errorMessage("Payment seemed to fail.")
                                            .build();
                                }
                                case "payment_intent.succeeded" ->
                                        pd.success(true)
                                                .build();
                                case "payment_intent.canceled"  ->
                                        pd.success(false)
                                                .errorMessage("Payment was cancelled")
                                                .build();
                                default ->
                                        pd.success(false)
                                                .errorMessage("Unknown event type: %s"
                                                        .formatted(event.getType()))
                                                .build();
                            };
                            // idempotency: check if event.getId() already processed in your DB
                            // fulfill order / mark payment paid using pi.getId(), pi.getAmount(), pi.getMetadata(), etc.
                        }
                        default -> PaymentData.builder().success(false)
                                .errorMessage("Unknown event type: %s"
                                        .formatted(event.getType()))
                                .build();
                    })
                    .orElseGet(() -> PaymentData.builder().success(false)
                            .errorMessage("No event type provided.")
                            .build());

        } catch (SignatureVerificationException e) {
            log.error("Error - invalid stripe signature [redacted].");
            return PaymentData.builder()
                    .errorMessage("Stripe error: invalid signature.")
                    .success(false)
                    .build();
        } catch (Exception e) {
            log.error("Unknown error processing stripe of type {} [redacted]", e.getClass().getName());
            return PaymentData.builder()
                    .errorMessage("Stripe error: invalid signature.")
                    .success(false)
                    .build();
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

}
