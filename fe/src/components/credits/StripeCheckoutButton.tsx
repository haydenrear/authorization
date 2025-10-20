'use client'

import { useState } from 'react'
import { LoadingSpinner } from '../common/LoadingSpinner'

export interface StripeCheckoutButtonProps {
  onCheckout: (amount: number) => Promise<string | null>
  isLoading?: boolean
}

export function StripeCheckoutButton({ onCheckout, isLoading = false }: StripeCheckoutButtonProps) {
  const [selectedAmount, setSelectedAmount] = useState<number | null>(null)
  const [customAmount, setCustomAmount] = useState('')
  const [isProcessing, setIsProcessing] = useState(false)

  const presetAmounts = [10, 25, 50, 100]

  const handleCheckout = async (amount: number) => {
    setIsProcessing(true)
    try {
      const checkoutUrl = await onCheckout(amount)
      if (checkoutUrl) {
        window.location.href = checkoutUrl
      }
    } catch (error) {
      console.error('Checkout failed:', error)
    } finally {
      setIsProcessing(false)
    }
  }

  const handleCustomCheckout = async () => {
    const amount = parseFloat(customAmount)
    if (isNaN(amount) || amount <= 0) {
      alert('Please enter a valid amount')
      return
    }
    await handleCheckout(amount)
  }

  return (
    <div className="bg-white rounded-lg border border-gray-200 p-6">
      <h3 className="text-xl font-semibold text-gray-900 mb-4">Add Credits</h3>

      <div className="mb-6">
        <p className="text-sm text-gray-600 mb-3">Select an amount:</p>
        <div className="grid grid-cols-2 md:grid-cols-4 gap-3 mb-4">
          {presetAmounts.map((amount) => (
            <button
              key={amount}
              onClick={() => handleCheckout(amount)}
              disabled={isLoading || isProcessing}
              className="p-3 border-2 border-gray-200 rounded-lg hover:border-blue-500 hover:bg-blue-50 disabled:opacity-50 disabled:cursor-not-allowed transition-colors font-semibold text-gray-900"
            >
              ${amount}
            </button>
          ))}
        </div>
      </div>

      <div className="mb-4">
        <p className="text-sm text-gray-600 mb-2">Or enter a custom amount:</p>
        <div className="flex gap-2">
          <div className="relative flex-1">
            <span className="absolute left-3 top-1/2 transform -translate-y-1/2 text-gray-500">
              $
            </span>
            <input
              type="number"
              value={customAmount}
              onChange={(e) => setCustomAmount(e.target.value)}
              placeholder="0.00"
              disabled={isLoading || isProcessing}
              step="0.01"
              min="0"
              className="w-full pl-6 pr-4 py-2 border border-gray-300 rounded-lg focus:ring-blue-500 focus:border-blue-500 disabled:bg-gray-100"
            />
          </div>
          <button
            onClick={handleCustomCheckout}
            disabled={!customAmount || isLoading || isProcessing}
            className="px-6 py-2 bg-blue-600 text-white rounded-lg hover:bg-blue-700 disabled:bg-gray-400 disabled:cursor-not-allowed font-semibold flex items-center gap-2"
          >
            {isProcessing && <span className="w-4 h-4 border-2 border-white border-t-transparent rounded-full animate-spin" />}
            Checkout
          </button>
        </div>
      </div>

      <p className="text-xs text-gray-500">
        You will be redirected to Stripe to complete your purchase securely.
      </p>
    </div>
  )
}
