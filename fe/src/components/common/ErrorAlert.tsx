'use client'

import { ApiError } from '@/utils/errorHandler'

export interface ErrorAlertProps {
  error: ApiError | null
  onDismiss?: () => void
  showDetails?: boolean
}

export function ErrorAlert({ error, onDismiss, showDetails = false }: ErrorAlertProps) {
  if (!error) return null

  return (
    <div className="bg-red-50 border border-red-200 rounded-lg p-4 mb-4">
      <div className="flex items-start justify-between">
        <div className="flex-1">
          <h3 className="font-semibold text-red-800">Error</h3>
          <p className="text-red-700 text-sm mt-1">{error.message}</p>
          {showDetails && error.details && (
            <pre className="text-xs text-red-600 mt-2 bg-red-100 p-2 rounded overflow-auto max-h-40">
              {JSON.stringify(error.details, null, 2)}
            </pre>
          )}
        </div>
        {onDismiss && (
          <button
            onClick={onDismiss}
            className="ml-2 text-red-600 hover:text-red-800 font-semibold"
            aria-label="Close"
          >
            ×
          </button>
        )}
      </div>
    </div>
  )
}
