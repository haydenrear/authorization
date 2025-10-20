'use client'

import { useState, useRef, useEffect } from 'react'
import { TokenCreateRequest, TokenResponse } from '@/types/token'
import { LoadingSpinner } from '../common/LoadingSpinner'
import { SuccessAlert } from '../common/SuccessAlert'
import { SCOPES, MESSAGES } from '@/utils/constants'

export interface TokenCreateModalProps {
  isOpen: boolean
  isLoading?: boolean
  onClose: () => void
  onCreate: (request: TokenCreateRequest) => Promise<TokenResponse | null>
}

export function TokenCreateModal({
  isOpen,
  isLoading = false,
  onClose,
  onCreate,
}: TokenCreateModalProps) {
  const dialogRef = useRef<HTMLDialogElement>(null)
  const [name, setName] = useState('')
  const [scope, setScope] = useState(`${SCOPES.API_READ} ${SCOPES.API_WRITE}`)
  const [createdToken, setCreatedToken] = useState<TokenResponse | null>(null)
  const [showSuccess, setShowSuccess] = useState(false)

  useEffect(() => {
    if (isOpen && dialogRef.current) {
      dialogRef.current.showModal()
    } else if (!isOpen && dialogRef.current) {
      dialogRef.current.close()
    }
  }, [isOpen])

  const handleCreate = async (e: React.FormEvent) => {
    e.preventDefault()

    const token = await onCreate({
      grant_type: 'urn:ietf:params:oauth:grant-type:jwt-bearer',
      name: name || undefined,
      scope,
    })

    if (token) {
      setCreatedToken(token)
      setShowSuccess(true)
      setName('')
      setScope(`${SCOPES.API_READ} ${SCOPES.API_WRITE}`)
    }
  }

  const handleClose = () => {
    if (!isLoading && !showSuccess) {
      setCreatedToken(null)
      setShowSuccess(false)
      onClose()
    }
  }

  return (
    <dialog
      ref={dialogRef}
      className="rounded-lg shadow-lg backdrop:bg-black backdrop:bg-opacity-50 max-w-2xl w-full"
      onClick={(e) => {
        if (e.target === dialogRef.current && !showSuccess) {
          handleClose()
        }
      }}
    >
      <div className="p-6">
        {showSuccess && createdToken ? (
          <div>
            <h2 className="text-2xl font-bold text-gray-900 mb-4">API Key Created</h2>
            <p className="text-gray-600 mb-4">
              Your new API key has been created. Copy it now and store it safely. You won't be able to see it again.
            </p>

            <div className="bg-gray-900 rounded-lg p-4 mb-4 break-all">
              <code className="text-green-400 font-mono text-sm">
                {createdToken.access_token}
              </code>
            </div>

            <div className="flex justify-end gap-3">
              <button
                onClick={() => {
                  navigator.clipboard.writeText(createdToken.access_token)
                }}
                className="px-4 py-2 bg-blue-600 text-white rounded-lg hover:bg-blue-700"
              >
                Copy to Clipboard
              </button>
              <button
                onClick={handleClose}
                className="px-4 py-2 bg-gray-600 text-white rounded-lg hover:bg-gray-700"
              >
                Done
              </button>
            </div>
          </div>
        ) : (
          <form onSubmit={handleCreate}>
            <h2 className="text-2xl font-bold text-gray-900 mb-4">Create API Key</h2>

            <div className="space-y-4 mb-6">
              <div>
                <label htmlFor="name" className="block text-sm font-medium text-gray-700 mb-2">
                  Name (Optional)
                </label>
                <input
                  id="name"
                  type="text"
                  value={name}
                  onChange={(e) => setName(e.target.value)}
                  placeholder="e.g., Production API Key"
                  disabled={isLoading}
                  className="w-full px-4 py-2 border border-gray-300 rounded-lg focus:ring-blue-500 focus:border-blue-500 disabled:bg-gray-100"
                />
              </div>

              <div>
                <label htmlFor="scope" className="block text-sm font-medium text-gray-700 mb-2">
                  Scopes
                </label>
                <textarea
                  id="scope"
                  value={scope}
                  onChange={(e) => setScope(e.target.value)}
                  disabled={isLoading}
                  rows={3}
                  className="w-full px-4 py-2 border border-gray-300 rounded-lg focus:ring-blue-500 focus:border-blue-500 disabled:bg-gray-100 font-mono text-sm"
                />
                <p className="text-xs text-gray-500 mt-1">Space-separated scopes (e.g., api:read api:write)</p>
              </div>
            </div>

            <div className="flex justify-end gap-3">
              <button
                type="button"
                onClick={handleClose}
                disabled={isLoading}
                className="px-4 py-2 rounded border border-gray-300 text-gray-700 hover:bg-gray-50 disabled:opacity-50"
              >
                Cancel
              </button>
              <button
                type="submit"
                disabled={isLoading}
                className="px-4 py-2 bg-blue-600 text-white rounded-lg hover:bg-blue-700 disabled:opacity-50 flex items-center gap-2"
              >
                {isLoading && <span className="w-4 h-4 border-2 border-white border-t-transparent rounded-full animate-spin" />}
                Create
              </button>
            </div>
          </form>
        )}
      </div>
    </dialog>
  )
}
