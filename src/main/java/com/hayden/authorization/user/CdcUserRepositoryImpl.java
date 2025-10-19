package com.hayden.authorization.user;

import com.hayden.commitdiffmodel.stripe.PaymentData;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Lazy;
import org.springframework.stereotype.Repository;
import org.springframework.transaction.annotation.Isolation;
import org.springframework.transaction.annotation.Transactional;

import java.time.Instant;
import java.util.ArrayList;
import java.util.Optional;

/**
 * Implementation of custom CdcUser repository methods.
 * Handles atomic credit operations using database transactions.
 */
@Repository
@RequiredArgsConstructor
@Slf4j
public class CdcUserRepositoryImpl implements CdcUserRepositoryCustom {

    @Autowired
    @Lazy
    private CdcUserRepository userRepository;

    /**
     * Atomically decrements the user's credits if they have enough.
     * Uses SERIALIZABLE isolation to prevent race conditions.
     */
    @Override
    @Transactional(isolation = Isolation.SERIALIZABLE)
    public Optional<Integer> getAndDecrementCredits(CdcUser.CdcUserId userId, int amount) {
        // Fetch the user within the transaction
        Optional<CdcUser> userOptional = userRepository.findById(userId);

        if (userOptional.isEmpty()) {
            log.warn("User not found for credits decrement: {}", userId);
            return Optional.empty();
        }

        CdcUser user = userOptional.get();
        CdcUser.Credits credits = user.getCredits();

        // Initialize credits if null
        if (credits == null) {
            log.debug("User {} has no credits object, initializing", userId);
            credits = new CdcUser.Credits(0, 0, Instant.now());
            user.setCredits(credits);
        }

        // Check if user has enough credits
        if (credits.current() < amount) {
            log.debug("User {} has insufficient credits: {} < {}", userId, credits.current(), amount);
            return Optional.empty();
        }

        // Decrement credits
        int newBalance = credits.current() - amount;
        int newHistory = credits.history() + amount;
        CdcUser.Credits updatedCredits = new CdcUser.Credits(newBalance, newHistory, Instant.now());
        user.setCredits(updatedCredits);

        // Save the updated user - will be flushed at transaction end
        userRepository.save(user);
        log.info("User {} credits decremented: {} -> {} (consumed: {})", 
                 userId, credits.current(), newBalance, amount);

        return Optional.of(newBalance);
    }

    /**
     * Atomically increments the user's credits.
     * Uses SERIALIZABLE isolation to prevent race conditions.
     */
    @Override
    @Transactional(isolation = Isolation.SERIALIZABLE)
    public int getAndIncrementCredits(CdcUser.CdcUserId userId, int amount, PaymentData event) {
        // Fetch the user within the transaction
        Optional<CdcUser> userOptional = userRepository.findById(userId);

        if (userOptional.isEmpty()) {
            log.warn("User not found for credits increment: {}", userId);
            return 0;
        }

        CdcUser user = userOptional.get();

        if (user.alreadyProcessed(event.idempotentId())) {
            log.warn("User {} already processed: {}", userId, event.idempotentId());
            return 0;
        }

        CdcUser.Credits credits = user.getCredits();


        // Initialize credits if null
        if (credits == null) {
            log.debug("User {} has no credits object, initializing", userId);
            credits = new CdcUser.Credits(0, 0, Instant.now());
        }

        // Increment credits
        int newBalance = credits.current() + amount;
        int newHistory = credits.history();
        var p = new ArrayList<>(credits.paymentsProcessed());
        p.add(event.idempotentId());
        CdcUser.Credits updatedCredits = new CdcUser.Credits(newBalance, newHistory, Instant.now(), p);
        user.setCredits(updatedCredits);

        // Save the updated user - will be flushed at transaction end
        userRepository.save(user);
        log.info("User {} credits incremented: {} -> {} (added: {})", 
                 userId, credits.current(), newBalance, amount);

        return newBalance;
    }
}
