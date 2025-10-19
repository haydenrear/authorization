package com.hayden.authorization.stripe;

import com.fasterxml.jackson.databind.ObjectMapper;
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

import java.util.ArrayList;
import java.util.List;
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
    private final ObjectMapper objectMapper;

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
                        .status(401)
                        .errorMessage(secretNotConfigured)
                        .build();
            }

            var sig = getSignatures(sigHeader);

            if (sig.stream().filter(Objects::nonNull).noneMatch(st -> Objects.equals(st, webhookSecret))) {
                return PaymentData.builder()
                        .success(false)
                        .errorMessage("Webhook secret did not match.")
                        .status(401)
                        .build();
            }

            Event event = Webhook.constructEvent(payload, sigHeader, webhookSecret);

            return Optional.ofNullable(event)
                    .flatMap(evt -> Optional.ofNullable(evt.getDataObjectDeserializer())
                            .flatMap(EventDataObjectDeserializer::getObject))
                    .map(so -> switch(so) {
                        case PaymentIntent pi ->
                                parsePaymentIntent(pi, event);
                        default -> PaymentData.builder().success(false)
                                .errorMessage("Unknown event type: %s"
                                        .formatted(event.getType()))
                                .status(200)
                                .build();
                    })
                    .orElseGet(() -> PaymentData.builder().success(false)
                            .errorMessage("No event type provided.")
                            .status(200)
                            .build());

        } catch (SignatureVerificationException e) {
            log.error("Error - invalid stripe signature [redacted].");
            return PaymentData.builder()
                    .errorMessage("Stripe error: invalid signature.")
                    .status(401)
                    .success(false)
                    .build();
        } catch (Exception e) {
            log.error("Unknown error processing stripe of type {} [redacted]", e.getClass().getName());
            return PaymentData.builder()
                    .errorMessage("Stripe error: invalid signature.")
                    .status(500)
                    .success(false)
                    .build();
        }
    }

    private PaymentData parsePaymentIntent(PaymentIntent pi, Event event) {
        var address = Optional.ofNullable(pi.getCustomerObject())
                .flatMap(c -> Optional.ofNullable(c.getAddress()))
                        .or(() -> Optional.ofNullable(pi.getShipping()).flatMap(s -> Optional.ofNullable(s.getAddress())))
                .map(add -> modelMapper.map(add, PaymentData.Address.class));
        var phone = Optional.ofNullable(pi.getCustomerObject())
                .flatMap(c -> Optional.ofNullable(c.getPhone()))
                .or(() -> Optional.ofNullable(pi.getShipping()).flatMap(s -> Optional.ofNullable(s.getPhone())));
        var name = Optional.ofNullable(pi.getCustomerObject())
                .flatMap(c -> Optional.ofNullable(c.getName()))
                .or(() -> Optional.ofNullable(pi.getShipping())
                        .flatMap(s -> Optional.ofNullable(s.getName())));
        var email = Optional.ofNullable(pi.getCustomerObject())
                .flatMap(c -> Optional.ofNullable(c.getEmail()))
                .or(() -> Optional.ofNullable(pi.getReceiptEmail()))
                .or(() -> Optional.ofNullable(pi.getOnBehalfOfObject())
                        .flatMap(ac -> Optional.ofNullable(ac.getEmail())));

        if (!pi.getCaptureMethod().startsWith("automatic")) {
            return PaymentData.builder()
                    .status(400)
                    .success(false)
                    .errorMessage("Unknown capture method %s".formatted(pi.getCaptureMethod()))
                    .build();
        }

        var pd = PaymentData.builder()
                .idempotentId(event.getRequest().getIdempotencyKey())
                .sessionData(
                        PaymentData.SessionData
                                .builder()
                                .name(name.orElse(null))
                                .email(email.orElse(null))
                                .ph(phone.orElse(null))
                                .address(address.orElse(null))
                                .build()
                )
                .amountPaid(pi.getAmountReceived());

        return switch (event.getType()) {
            case "payment_intent.succeeded" ->
                    pd.success(true)
                            .status(200)
                            .build();
            case "payment_intent.payment_failed" ->
                    pd.success(false)
                            .amountPaid(0L)
                            .status(200)
                            .errorMessage("Payment seemed to fail.")
                            .build();
            case "payment_intent.canceled" ->
                    pd.success(false)
                            .amountPaid(0L)
                            .errorMessage("Payment was cancelled")
                            .status(200)
                            .build();
            default -> pd.success(false)
                    .amountPaid(0L)
                    .errorMessage("Unknown event type: %s"
                            .formatted(event.getType()))
                    .status(404)
                    .build();
        };
        // idempotency: check if event.getId() already processed in your DB
        // fulfill order / mark payment paid using pi.getId(), pi.getAmount(), pi.getMetadata(), etc.
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

    private static List<String> getSignatures(String sigHeader) {
        List<String> signatures = new ArrayList<String>();
        String[] items = sigHeader.split(",", -1);

        for (String item : items) {
            String[] itemParts = item.split("=", 2);
            if (itemParts[0].equals(Webhook.Signature.EXPECTED_SCHEME)) {
                signatures.add(itemParts[1]);
            }
        }

        return signatures;
    }
}
