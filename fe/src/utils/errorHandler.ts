import {OAuth2Error} from '@/types/oauth'

export interface ApiError {
    message: string
    status?: number
    code?: string
    details?: any
}

export function parseError(error: unknown): ApiError {
    if (typeof error === 'string') {
        return {
            message: error as string
        }
    }

    if (error instanceof Response) {
        return {
            message: `HTTP ${error.status}: ${error.statusText}`,
            status: error.status,
        }
    }

    // OAuth2 error object
    if (typeof error === 'object' && error !== null) {
        const err = error as Partial<OAuth2Error> & Record<string, any>

        if (err.error) {
            return {
                message: err.error_description || err.error,
                code: err.error,
                details: err,
            }
        }

        if (err.message) {
            return {
                message: err.message,
                details: error,
            }
        }
    }

    // String error
    if (typeof error === 'string') {
        return {message: error}
    }

    // Fallback
    return {
        message: 'An unexpected error occurred',
        details: error,
    }
}

export function isAuthError(error: ApiError): boolean {
    return error.status === 401 || error.status === 403
}

export function isNetworkError(error: ApiError): boolean {
    return error.status === 0 || error.status === undefined
}

export function isServerError(error: ApiError): boolean {
    return error.status ? error.status >= 500 : false
}

export class HttpError extends Error {
    constructor(
        public status: number,
        message: string,
        public response?: any
    ) {
        super(message)
        this.name = 'HttpError'
    }
}
