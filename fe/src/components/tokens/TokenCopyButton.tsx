'use client'

import { useState } from 'react'
import { MESSAGES } from '@/utils/constants'

export interface TokenCopyButtonProps {
  token: string
  label?: string
}

export function TokenCopyButton({ token, label = 'Copy' }: TokenCopyButtonProps) {
  const [copied, setCopied] = useState(false)

  const handleCopy = async () => {
    try {
      await navigator.clipboard.writeText(token)
      setCopied(true)
      setTimeout(() => setCopied(false), 2000)
    } catch (error) {
      console.error(MESSAGES.TOKEN_COPY_ERROR, error)
    }
  }

  return (
    <button
      onClick={handleCopy}
      className={`px-3 py-1 rounded text-sm font-medium transition-colors ${
        copied
          ? 'bg-green-100 text-green-800'
          : 'bg-gray-100 text-gray-700 hover:bg-gray-200'
      }`}
    >
      {copied ? '✓ Copied' : label}
    </button>
  )
}
