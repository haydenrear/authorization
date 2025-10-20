package com.hayden.authorization.credits;

import com.hayden.authorization.stripe.StripeWebhookService;
import com.hayden.authorization.user.CdcUser;
import com.hayden.authorization.user.CdcUserRepository;
import com.hayden.authorization.user.QCdcUser;
import com.hayden.commitdiffmodel.credits.CreditsResponse;
import com.hayden.commitdiffmodel.credits.GetAndDecrementCreditsRequest;
import com.hayden.commitdiffmodel.stripe.PaymentData;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.data.repository.query.FluentQuery;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.web.bind.annotation.*;

import java.util.Optional;
import java.util.UUID;

@RestController
@RequestMapping("/api/v1/credits")
@RequiredArgsConstructor
@Slf4j
public class CreditsController {

    private final CdcUserRepository userRepository;
    private final StripeWebhookService stripeWebhookService;

    /**
     * Stripe webhook handler for payment completion.
     * Validates the webhook signature and adds credits to the user's account.
     */
    @PostMapping("/stripe/add-credits")
    public ResponseEntity<Void> handleStripeWebhook(@RequestHeader("Stripe-Signature") String sigHeader,
                                                     @RequestBody String payload) {
            PaymentData event = stripeWebhookService.validateAndParseWebhook(payload, sigHeader);
        System.out.println(payload);
        
        if (event.isFailure()) {
            log.warn("Invalid or unverifiable Stripe webhook received");
            return ResponseEntity.status(event.status()).build();
        }

        if (event.sessionData() == null) {
            log.warn("Could not extract checkout session from webhook event");
            return ResponseEntity.badRequest().build();
        }

        PaymentData.SessionData session = event.sessionData();

        // Find the user by email
        String email = session.email();
        String name = session.name();

        if (email == null)
            email = UUID.randomUUID().toString();
        if (name == null)
            name = UUID.randomUUID().toString();

        var userOpt = userRepository.findBy(
                QCdcUser.cdcUser.email.eq(email)
                        .or(QCdcUser.cdcUser.email.eq(name))
                        .or(QCdcUser.cdcUser.principalId.principalId.eq(name))
                        .or(QCdcUser.cdcUser.principalId.principalId.eq(email)),
                FluentQuery.FetchableFluentQuery::all);

        if (userOpt.isEmpty()) {
            log.warn("User not found for email: {}", email);
            return ResponseEntity.status(HttpStatus.NOT_FOUND).build();
        }

        if (userOpt.size() > 1) {
            log.warn("Multiple users found for email: {} - not set up currently.", email);
        }

        CdcUser user = userOpt.getFirst();
        
        // Calculate credits to add based on the amount paid
        long amountCents = event.amountPaid();
        int creditsToAdd = stripeWebhookService.calculateCredits(amountCents);

        // Add credits to the user (atomically)
        int newBalance = userRepository.getAndIncrementCredits(user.getPrincipalId(), creditsToAdd, event);
        
        log.info("Stripe webhook processed: User {} now has {} credits (added {})", 
                 user.getEmail(), newBalance, creditsToAdd);

        return ResponseEntity.ok().build();
    }

    /**
     * Get current credits for the authenticated user.
     */
    @GetMapping(value = "/get-credits", produces = MediaType.APPLICATION_JSON_VALUE)
    public ResponseEntity<CreditsResponse> getCredits(@AuthenticationPrincipal Jwt authenticatedPrincipal) {
        if (authenticatedPrincipal == null) {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).build();
        }

        // Extract user ID from JWT
        String principalId = authenticatedPrincipal.getSubject();

        if (principalId == null) {
            log.warn("JWT missing required claims: client_id");
            return ResponseEntity.status(HttpStatus.NOT_FOUND).build();
        }

        CdcUser.CdcUserId userId = new CdcUser.CdcUserId(principalId, "cdc");
        
        // Fetch the user
        Optional<CdcUser> userOpt = userRepository.findById(userId);
        
        if (userOpt.isEmpty()) {
            log.warn("User not found: {}", userId);
            return ResponseEntity.status(HttpStatus.NOT_FOUND).build();
        }

        CdcUser user = userOpt.get();
        CdcUser.Credits credits = user.getCredits();

        // Initialize credits if null
        if (credits == null) {
            credits = new CdcUser.Credits(0, 0, null);
        }

        CreditsResponse response = CreditsResponse.builder()
                .hasCredits(credits.current() > 0)
                .remaining(credits.current())
                .userId(principalId)
                .build();

        return ResponseEntity.ok(response);
    }

    /**
     * Atomically decrements credits for the authenticated user.
     * Returns the new balance if successful, or 401 if insufficient credits.
     */
    @PostMapping(value = "/get-and-decrement", 
                 consumes = MediaType.APPLICATION_JSON_VALUE,
                 produces = MediaType.APPLICATION_JSON_VALUE)
    public ResponseEntity<CreditsResponse> getAndDecrement(
            @AuthenticationPrincipal Jwt authenticatedPrincipal,
            @RequestBody GetAndDecrementCreditsRequest request) {
        
        if (authenticatedPrincipal == null) {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).build();
        }

        // Extract user ID from JWT
        String principalId = authenticatedPrincipal.getSubject();
        String clientId = authenticatedPrincipal.getClaimAsString("client_id");
        
        if (principalId == null || clientId == null) {
            log.warn("JWT missing required claims: sub or client_id");
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).build();
        }

        CdcUser.CdcUserId userId = new CdcUser.CdcUserId(principalId, clientId);
        
        // Atomically decrement credits
        Optional<Integer> newBalanceOpt = userRepository.getAndDecrementCredits(userId, request.getAmount());
        
        if (newBalanceOpt.isEmpty()) {
            // Insufficient credits
            log.debug("User {} attempted to decrement credits but has insufficient balance", userId);
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
                    .body(CreditsResponse.builder()
                            .hasCredits(false)
                            .remaining(0)
                            .reason("INSUFFICIENT_CREDITS")
                            .userId(principalId)
                            .build());
        }

        int newBalance = newBalanceOpt.get();
        
        CreditsResponse response = CreditsResponse.builder()
                .hasCredits(true)
                .remaining(newBalance)
                .consumed(request.getAmount())
                .userId(principalId)
                .build();

        log.debug("User {} decremented credits by {}, new balance: {}", principalId, request.getAmount(), newBalance);
        return ResponseEntity.ok(response);
    }

}
