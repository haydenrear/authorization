'use client'

import { Transaction } from '@/types/credit'

export interface CreditHistoryProps {
  transactions: Transaction[]
  isLoading?: boolean
}

export function CreditHistory({ transactions, isLoading = false }: CreditHistoryProps) {
  const getTransactionTypeColor = (type: string) => {
    switch (type) {
      case 'purchase':
        return 'text-green-600 bg-green-50'
      case 'usage':
        return 'text-red-600 bg-red-50'
      default:
        return 'text-gray-600 bg-gray-50'
    }
  }

  const getTransactionTypeLabel = (type: string) => {
    switch (type) {
      case 'purchase':
        return 'Purchase'
      case 'usage':
        return 'Usage'
      default:
        return type
    }
  }

  const getTransactionTypeIcon = (type: string) => {
    switch (type) {
      case 'purchase':
        return '+'
      case 'usage':
        return '−'
      default:
        return '•'
    }
  }

  if (transactions.length === 0) {
    return (
      <div className="text-center py-12">
        <p className="text-gray-600">No transactions yet.</p>
      </div>
    )
  }

  return (
    <div className="bg-white rounded-lg border border-gray-200 overflow-hidden">
      <div className="px-6 py-4 border-b border-gray-200 bg-gray-50">
        <h3 className="font-semibold text-gray-900">Transaction History</h3>
      </div>

      <div className="divide-y divide-gray-200">
        {transactions.map((transaction) => (
          <div
            key={transaction.id}
            className="px-6 py-4 flex items-center justify-between hover:bg-gray-50 transition-colors"
          >
            <div className="flex-1">
              <div className="flex items-center gap-3">
                <div
                  className={`w-10 h-10 rounded-full flex items-center justify-center font-bold text-lg ${getTransactionTypeColor(
                    transaction.type
                  )}`}
                >
                  {getTransactionTypeIcon(transaction.type)}
                </div>

                <div className="flex-1 min-w-0">
                  <p className="font-medium text-gray-900">
                    {transaction.description}
                  </p>
                  <p className="text-sm text-gray-500">
                    {new Date(transaction.date).toLocaleString()}
                  </p>
                </div>
              </div>
            </div>

            <div className="text-right ml-4">
              <p
                className={`font-semibold ${
                  transaction.type === 'purchase' ? 'text-green-600' : 'text-red-600'
                }`}
              >
                {transaction.type === 'purchase' ? '+' : '−'}
                {transaction.amount.toFixed(2)}
              </p>
              <p className="text-sm text-gray-500">
                Balance: {transaction.balance_after.toFixed(2)}
              </p>
            </div>
          </div>
        ))}
      </div>
    </div>
  )
}
