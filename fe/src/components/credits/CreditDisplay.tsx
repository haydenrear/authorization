'use client'

import { CreditInfo } from '@/types/credit'

export interface CreditDisplayProps {
  credits: CreditInfo
}

export function CreditDisplay({ credits }: CreditDisplayProps) {
  return (
    <div className="bg-gradient-to-br from-blue-50 to-blue-100 border border-blue-200 rounded-lg p-8 mb-6">
      <p className="text-blue-600 text-sm font-medium mb-2">Current Balance</p>
      <h2 className="text-4xl font-bold text-blue-900 mb-2">
        {credits.balance.toFixed(2)}
      </h2>
      <p className="text-blue-700">
        {credits.currency}
      </p>
      <p className="text-blue-600 text-xs mt-3">
        Updated {new Date(credits.updated_at).toLocaleString()}
      </p>
    </div>
  )
}
