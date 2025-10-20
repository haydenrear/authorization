'use client'

import { useState } from 'react'
import { ConfirmDialog } from '../common/ConfirmDialog'
import { MESSAGES } from '@/utils/constants'

export interface TokenRevokeButtonProps {
  tokenName?: string
  onRevoke: () => Promise<void>
}

export function TokenRevokeButton({ tokenName, onRevoke }: TokenRevokeButtonProps) {
  const [isConfirmOpen, setIsConfirmOpen] = useState(false)
  const [isLoading, setIsLoading] = useState(false)

  const handleConfirm = async () => {
    setIsLoading(true)
    try {
      await onRevoke()
      setIsConfirmOpen(false)
    } catch (error) {
      console.error(MESSAGES.TOKEN_REVOKE_ERROR, error)
    } finally {
      setIsLoading(false)
    }
  }

  return (
    <>
      <button
        onClick={() => setIsConfirmOpen(true)}
        className="px-3 py-1 rounded text-sm font-medium bg-red-100 text-red-700 hover:bg-red-200 transition-colors"
      >
        Revoke
      </button>

      <ConfirmDialog
        title="Revoke API Key?"
        message={`Are you sure you want to revoke ${tokenName ? `"${tokenName}"` : 'this API key'}? This action cannot be undone.`}
        confirmLabel="Revoke"
        cancelLabel="Cancel"
        isDangerous
        isOpen={isConfirmOpen}
        isLoading={isLoading}
        onConfirm={handleConfirm}
        onCancel={() => setIsConfirmOpen(false)}
      />
    </>
  )
}
