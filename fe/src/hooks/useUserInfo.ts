'use client'

import { useState, useCallback, useEffect } from 'react'
import { userService } from '@/services/userService'
import { UserInfo, UserUpdateRequest } from '@/types/user'
import { parseError, ApiError } from '@/utils/errorHandler'
import {useAuth} from "@/hooks/useAuth";

export interface UseUserInfoReturn {
  user: UserInfo | null
  isLoading: boolean
  error: ApiError | null
  fetchUser: () => Promise<void>
  updateEmail: (email: string) => Promise<void>
  updateUsername: (username: string) => Promise<void>
  clearError: () => void
}

export function useUserInfo(): UseUserInfoReturn {
  const [user, setUser] = useState<UserInfo | null>(null)
  const [isLoading, setIsLoading] = useState(false)
  const [error, setError] = useState<ApiError | null>(null)

  useEffect(() => {
    // Try to load cached user info first
    const cached = userService.getCachedUserInfo()
    if (cached) {
      setUser(cached)
    }
  }, [useAuth])

  const fetchUser = useCallback(async () => {
    setIsLoading(true)
    setError(null)
    try {
      const userInfo = await userService.fetchUserInfo()
      setUser(userInfo)
    } catch (err) {
      const apiError = parseError(err)
      setError(apiError)
    } finally {
      setIsLoading(false)
    }
  }, [useAuth])

  const updateEmail = useCallback(async (email: string) => {
    setIsLoading(true)
    setError(null)
    try {
      const updated = await userService.updateEmail(email)
      setUser(updated)
    } catch (err) {
      const apiError = parseError(err)
      setError(apiError)
      throw apiError
    } finally {
      setIsLoading(false)
    }
  }, [useAuth])

  const updateUsername = useCallback(async (username: string) => {
    setIsLoading(true)
    setError(null)
    try {
      const updated = await userService.updateUsername(username)
      setUser(updated)
    } catch (err) {
      const apiError = parseError(err)
      setError(apiError)
      throw apiError
    } finally {
      setIsLoading(false)
    }
  }, [useAuth])

  const clearError = useCallback(() => {
    setError(null)
  }, [])

  return {
    user,
    isLoading,
    error,
    fetchUser,
    updateEmail,
    updateUsername,
    clearError,
  }
}
