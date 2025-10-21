'use client'

import { useState, useCallback } from 'react'
import { creditService } from '@/services/creditService'
import { CreditInfo, Transaction } from '@/types/credit'
import { parseError, ApiError } from '@/utils/errorHandler'
import {useAuth} from "@/hooks/useAuth";

export interface UseCreditsReturn {
  credits: CreditInfo | null
  transactions: Transaction[]
  isLoading: boolean
  isCheckingOut: boolean
  error: ApiError | null
  fetchCredits: () => Promise<void>
  fetchTransactions: (limit?: number, offset?: number) => Promise<void>
  initiateCheckout: (amount: number) => Promise<string | null>
  clearError: () => void
}

export function useCredits(): UseCreditsReturn {
  const [credits, setCredits] = useState<CreditInfo | null>(null)
  const [transactions, setTransactions] = useState<Transaction[]>([])
  const [isLoading, setIsLoading] = useState(false)
  const [isCheckingOut, setIsCheckingOut] = useState(false)
  const [error, setError] = useState<ApiError | null>(null)

  const fetchCredits = useCallback(async () => {
    setIsLoading(true)
    setError(null)
    try {
      const creditInfo = await creditService.fetchCredits()
      setCredits(creditInfo)
    } catch (err) {
      const apiError = parseError(err)
      setError(apiError)
    } finally {
      setIsLoading(false)
    }
  }, [useAuth])

  const fetchTransactions = useCallback(async (limit = 50, offset = 0) => {
    setIsLoading(true)
    setError(null)
    try {
      const txns = await creditService.fetchTransactionHistory(limit, offset)
      setTransactions(txns)
    } catch (err) {
      const apiError = parseError(err)
      setError(apiError)
    } finally {
      setIsLoading(false)
    }
  }, [useAuth])

  const initiateCheckout = useCallback(async (amount: number): Promise<string | null> => {
    setIsCheckingOut(true)
    setError(null)
    try {
      const session = await creditService.getStripeCheckoutLink(amount)
      // Return the checkout URL
      return session.url
    } catch (err) {
      const apiError = parseError(err)
      setError(apiError)
      return null
    } finally {
      setIsCheckingOut(false)
    }
  }, [useAuth])

  const clearError = useCallback(() => {
    setError(null)
  }, [])

  return {
    credits,
    transactions,
    isLoading,
    isCheckingOut,
    error,
    fetchCredits,
    fetchTransactions,
    initiateCheckout,
    clearError
  }
}
