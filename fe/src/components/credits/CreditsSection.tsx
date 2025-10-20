'use client'

import { useState, useEffect } from 'react'
import { CreditDisplay } from './CreditDisplay'
import { StripeCheckoutButton } from './StripeCheckoutButton'
import { CreditHistory } from './CreditHistory'
import { LoadingSpinner } from '../common/LoadingSpinner'
import { UseCreditsReturn } from '@/hooks/useCredits'

export interface CreditsSectionProps {
  credits: UseCreditsReturn
}

export function CreditsSection({ credits }: CreditsSectionProps) {
  const [showHistory, setShowHistory] = useState(false)

  useEffect(() => {
    if (showHistory && credits.transactions.length === 0) {
      credits.fetchTransactions()
    }
  }, [showHistory])

  return (
    <div>
      {credits.credits && (
        <>
          <CreditDisplay credits={credits.credits} />

          <div className="grid md:grid-cols-3 gap-6 mb-6">
            <div className="bg-white rounded-lg border border-gray-200 p-6">
              <p className="text-gray-600 text-sm mb-1">Purchases</p>
              <p className="text-2xl font-bold text-green-600">$0.00</p>
            </div>
            <div className="bg-white rounded-lg border border-gray-200 p-6">
              <p className="text-gray-600 text-sm mb-1">Usage</p>
              <p className="text-2xl font-bold text-red-600">$0.00</p>
            </div>
            <div className="bg-white rounded-lg border border-gray-200 p-6">
              <p className="text-gray-600 text-sm mb-1">Net Balance</p>
              <p className="text-2xl font-bold text-blue-600">
                ${credits.credits.balance.toFixed(2)}
              </p>
            </div>
          </div>
        </>
      )}

      <StripeCheckoutButton
        onCheckout={credits.initiateCheckout}
        isLoading={credits.isCheckingOut}
      />

      <div className="mt-6">
        <button
          onClick={() => setShowHistory(!showHistory)}
          className="text-blue-600 hover:text-blue-700 font-medium text-sm"
        >
          {showHistory ? 'Hide' : 'Show'} Transaction History
        </button>

        {showHistory && (
          <div className="mt-4">
            {credits.isLoading ? (
              <LoadingSpinner message="Loading transactions..." />
            ) : (
              <CreditHistory
                transactions={credits.transactions}
                isLoading={credits.isLoading}
              />
            )}
          </div>
        )}
      </div>
    </div>
  )
}
