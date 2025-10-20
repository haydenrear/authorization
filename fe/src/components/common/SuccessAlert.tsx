'use client'

import { useEffect, useState } from 'react'

export interface SuccessAlertProps {
  message: string
  duration?: number
  onDismiss?: () => void
}

export function SuccessAlert({ message, duration = 5000, onDismiss }: SuccessAlertProps) {
  const [isVisible, setIsVisible] = useState(true)

  useEffect(() => {
    if (duration && duration > 0) {
      const timer = setTimeout(() => {
        setIsVisible(false)
        onDismiss?.()
      }, duration)

      return () => clearTimeout(timer)
    }
  }, [duration, onDismiss])

  if (!isVisible) return null

  return (
    <div className="bg-green-50 border border-green-200 rounded-lg p-4 mb-4">
      <div className="flex items-start justify-between">
        <div className="flex-1">
          <h3 className="font-semibold text-green-800">Success</h3>
          <p className="text-green-700 text-sm mt-1">{message}</p>
        </div>
        <button
          onClick={() => {
            setIsVisible(false)
            onDismiss?.()
          }}
          className="ml-2 text-green-600 hover:text-green-800 font-semibold"
          aria-label="Close"
        >
          ×
        </button>
      </div>
    </div>
  )
}
