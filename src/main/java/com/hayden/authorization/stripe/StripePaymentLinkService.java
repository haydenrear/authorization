package com.hayden.authorization.stripe;

import com.hayden.utilitymodule.result.Result;
import com.hayden.utilitymodule.result.error.SingleError;
import com.stripe.Stripe;
import com.stripe.exception.StripeException;
import com.stripe.model.PaymentLink;
import com.stripe.param.PaymentLinkCreateParams;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Service;

@Service
@RequiredArgsConstructor
@Slf4j
public class StripePaymentLinkService {

    private final StripeConfigProps stripeConfig;

    public record PaymentError(String getMessage) implements SingleError { }

    public Result<PaymentLink, PaymentError> createPaymentLink() {

        PaymentLinkCreateParams params =
                PaymentLinkCreateParams.builder()
                        .addLineItem(
                                PaymentLinkCreateParams.LineItem.builder()
                                        .setPrice("price_1MoC3TLkdIwHu7ixcIbKelAC")
                                        .setQuantity(1L)
                                        .build()
                        )
                        .build();

        try {
            PaymentLink paymentLink = PaymentLink.create(params);
            return Result.ok(paymentLink);
        } catch (StripeException e) {
            log.error("Error creating Stripe PaymentLink", e);
            return Result.err(new PaymentError(e.getMessage()));
        }
    }

}
