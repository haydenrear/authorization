package com.hayden.authorization.stripe;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.stereotype.Component;

/**
 * Configuration properties for Stripe integration.
 * Properties should be prefixed with "stripe" in application.yml
 */
@Component
@ConfigurationProperties(prefix = "stripe")
@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class StripeConfigProps {

    /**
     * Stripe API key for server-side operations
     */
    private String apiKey;

    /**
     * Stripe webhook signing secret used to validate webhook signatures
     */
    private String webhookSecret;

    /**
     * Stripe webhook endpoint secret (alternative name for webhookSecret)
     */
    private String endpointSecret;

    /**
     * Number of credits to add per $1 (cent converted). Default: 10 credits per cent.
     * So a $10 payment (1000 cents) would add 10,000 credits.
     */
    private int creditsPerCent = 10;

    /**
     * Get the actual webhook secret to use, preferring endpointSecret if both are set
     */
    public String getWebhookSecretToUse() {
        return endpointSecret != null && !endpointSecret.isEmpty() ? endpointSecret : webhookSecret;
    }
}
