'use client'

import {useState, useCallback, useEffect} from 'react'
import {authService} from '@/services/authService'
import {parseError, ApiError} from '@/utils/errorHandler'
import {jwtService} from "@/services/jwtService";
import {JwtPayload} from "jsonwebtoken";

export interface UseAuthReturn {
    token: string | null
    isLoading: boolean
    error: ApiError | null
    getToken: () => Promise<string | null>
    setToken: (token: string, expiresIn: number) => void
    clearToken: () => void
    isTokenValid: () => boolean
}

export function useAuth(): UseAuthReturn {
    const [token, setTokenState] = useState<string | null>(null)
    const [isLoading, setIsLoading] = useState(false)
    const [error, setError] = useState<ApiError | null>(null)

    useEffect(() => {
        // Initialize token from storage
        const initToken = async () => {
            const token = jwtService.getTokenFromParam()
            if (token) {
                authService.setUserAccessToken(token)
                setTokenState(token)
            } else {
                const storedToken = authService.getAccessToken()
                setTokenState(storedToken)
            }
        }
        initToken()
            .catch(t => console.error("Error initializing token", t))
            .then(_ => console.debug("Initialized token."))
    }, [])

    const getToken = useCallback(async (): Promise<string | null> => {
        setIsLoading(true)
        setError(null)
        try {
            const token = authService.getAccessToken()
            setTokenState(token)
            return token
        } catch (err) {
            const apiError = parseError(err)
            setError(apiError)
            return null
        } finally {
            setIsLoading(false)
        }
    }, [])

    const setToken = useCallback((token: string, expiresIn: number) => {
        authService.setUserAccessToken(token, expiresIn)
        setTokenState(token)
        setError(null)
    }, [])

    const clearToken = useCallback(() => {
        authService.clearToken()
        setTokenState(null)
        setError(null)
    }, [])

    const isTokenValid = useCallback((): boolean => {
        return !!token && !authService.isTokenExpired()
    }, [token])

    return {
        token,
        isLoading,
        error,
        getToken,
        setToken,
        clearToken,
        isTokenValid,
    }
}
