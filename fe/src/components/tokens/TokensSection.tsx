'use client'

import { useState } from 'react'
import { TokenList } from './TokenList'
import { TokenCreateModal } from './TokenCreateModal'
import { LoadingSpinner } from '../common/LoadingSpinner'
import { SuccessAlert } from '../common/SuccessAlert'
import { MESSAGES } from '@/utils/constants'
import { UseTokensReturn } from '@/hooks/useTokens'

export interface TokensSectionProps {
  tokens: UseTokensReturn
}

export function TokensSection({ tokens }: TokensSectionProps) {
  const [isModalOpen, setIsModalOpen] = useState(false)
  const [successMessage, setSuccessMessage] = useState<string | null>(null)

  const handleCreateToken = async (request: any) => {
    const result = await tokens.createToken(request)
    if (result) {
      setSuccessMessage(MESSAGES.TOKEN_CREATED)
      setIsModalOpen(false)
    }
    return result
  }

  const handleRevokeToken = async (jti: string) => {
    try {
      await tokens.revokeToken(jti)
      setSuccessMessage(MESSAGES.TOKEN_REVOKED)
    } catch (error) {
      // Error is already in tokens.error
    }
  }

  return (
    <div>
      {successMessage && (
        <SuccessAlert
          message={successMessage}
          onDismiss={() => setSuccessMessage(null)}
        />
      )}

      <div className="mb-6">
        <button
          onClick={() => setIsModalOpen(true)}
          className="px-6 py-2 bg-blue-600 text-white rounded-lg hover:bg-blue-700 font-medium"
        >
          Create API Key
        </button>
      </div>

      {tokens.isLoading ? (
        <LoadingSpinner message="Loading API keys..." />
      ) : (
        <TokenList tokens={tokens.tokens} onRevoke={handleRevokeToken} />
      )}

      <TokenCreateModal
        isOpen={isModalOpen}
        isLoading={tokens.isCreating}
        onClose={() => setIsModalOpen(false)}
        onCreate={handleCreateToken}
      />
    </div>
  )
}
