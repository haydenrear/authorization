export interface CreditInfo {
  balance: number
  currency: string
  updated_at: string
}

export interface Transaction {
  id: string
  amount: number
  type: 'purchase' | 'usage'
  description: string
  date: string
  balance_after: number
}

export interface StripeCheckoutSession {
  url: string
  session_id: string
}
