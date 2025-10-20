import { apiClient } from './apiClient'
import { authConfig } from '@/config/authConfig'
import { CreditInfo, Transaction, StripeCheckoutSession } from '@/types/credit'

class CreditService {
  async fetchCredits(): Promise<CreditInfo> {
    try {
      const credits = await apiClient.get<CreditInfo>(
        authConfig.api.creditsEndpoint
      )
      return credits
    } catch (error) {
      console.error('Failed to fetch credits:', error)
      throw error
    }
  }

  async fetchTransactionHistory(limit: number = 50, offset: number = 0): Promise<Transaction[]> {
    try {
      const transactions = await apiClient.get<Transaction[]>(
        `${authConfig.api.creditsEndpoint}/transactions`,
        {
          params: { limit, offset },
        }
      )
      return transactions
    } catch (error) {
      console.error('Failed to fetch transaction history:', error)
      throw error
    }
  }

  async getStripeCheckoutLink(amount: number): Promise<StripeCheckoutSession> {
    try {
      const session = await apiClient.post<StripeCheckoutSession>(
        authConfig.api.stripeCheckoutEndpoint,
        { amount }
      )
      return session
    } catch (error) {
      console.error('Failed to get checkout link:', error)
      throw error
    }
  }

  async handleCheckoutReturn(): Promise<boolean> {
    // Called after user returns from Stripe checkout
    // Verify the checkout session and update credits
    try {
      await this.fetchCredits()
      return true
    } catch (error) {
      console.error('Failed to verify checkout:', error)
      return false
    }
  }
}

export const creditService = new CreditService()
