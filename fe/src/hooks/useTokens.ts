'use client'

import { useState, useCallback, useEffect } from 'react'
import { jwtService } from '@/services/jwtService'
import { Token, TokenCreateRequest, TokenResponse } from '@/types/token'
import { parseError, ApiError } from '@/utils/errorHandler'
import {useAuth} from "@/hooks/useAuth";

export interface UseTokensReturn {
  tokens: Token[]
  isLoading: boolean
  isCreating: boolean
  error: ApiError | null
  fetchTokens: () => Promise<void>
  createToken: (request: TokenCreateRequest) => Promise<TokenResponse | null>
  revokeToken: (jti: string) => Promise<void>
  clearError: () => void
}

export function useTokens(): UseTokensReturn {
  const [tokens, setTokens] = useState<Token[]>([])
  const [isLoading, setIsLoading] = useState(false)
  const [isCreating, setIsCreating] = useState(false)
  const [error, setError] = useState<ApiError | null>(null)

  const fetchTokens = useCallback(async () => {
    setIsLoading(true)
    setError(null)
    try {
      const fetchedTokens = await jwtService.listTokens()
      setTokens(fetchedTokens)
    } catch (err) {
      const apiError = parseError(err)
      setError(apiError)
    } finally {
      setIsLoading(false)
    }
  }, [useAuth])

  const createToken = useCallback(
    async (request: TokenCreateRequest): Promise<TokenResponse | null> => {
      setIsCreating(true)
      setError(null)
      try {
        const newToken = await jwtService.createToken(request)
        // Refresh the token list
        await fetchTokens()
        return newToken
      } catch (err) {
        const apiError = parseError(err)
        setError(apiError)
        return null
      } finally {
        setIsCreating(false)
      }
    },
    [fetchTokens]
  )

  const revokeToken = useCallback(
    async (jti: string) => {
      setError(null)
      try {
        await jwtService.revokeToken(jti)
        // Remove from local state
        setTokens((prev) => prev.filter((t) => t.jti !== jti))
      } catch (err) {
        const apiError = parseError(err)
        setError(apiError)
        throw apiError
      }
    },
    [useAuth])

  const clearError = useCallback(() => {
    setError(null)
  }, [])

  return {
    tokens,
    isLoading,
    isCreating,
    error,
    fetchTokens,
    createToken,
    revokeToken,
    clearError,
  }
}
