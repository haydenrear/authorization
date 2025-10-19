package com.hayden.authorization.user;

import java.util.Optional;

/**
 * Custom repository interface for CdcUser operations that require special handling,
 * such as atomic credit operations with advisory locks.
 */
public interface CdcUserRepositoryCustom {

    /**
     * Atomically decrements the user's credits if they have enough credits.
     * Uses database advisory locking to prevent race conditions.
     *
     * This operation:
     * 1. Acquires an advisory lock on the user
     * 2. Checks if the user has at least `amount` credits
     * 3. If yes, decrements the credits and returns the new balance
     * 4. If no, returns empty Optional (insufficient credits)
     * 5. Releases the lock
     *
     * @param userId     the user ID (composite key)
     * @param amount     the number of credits to decrement
     * @return Optional containing the new credit balance if successful, empty if insufficient credits
     */
    Optional<Integer> getAndDecrementCredits(CdcUser.CdcUserId userId, int amount);

    /**
     * Atomically increments the user's credits.
     * Uses database advisory locking to prevent race conditions.
     *
     * This operation:
     * 1. Acquires an advisory lock on the user
     * 2. Increments the user's credits by the specified amount
     * 3. Updates the lastUpdated timestamp
     * 4. Returns the new balance
     * 5. Releases the lock
     *
     * @param userId the user ID (composite key)
     * @param amount the number of credits to add
     * @return the new credit balance after incrementing
     */
    int getAndIncrementCredits(CdcUser.CdcUserId userId, int amount);
}
