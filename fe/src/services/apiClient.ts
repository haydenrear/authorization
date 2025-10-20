import { authConfig } from '@/config/authConfig'
import { HttpError, parseError } from '@/utils/errorHandler'
import { API_TIMEOUTS } from '@/utils/constants'

export interface RequestOptions extends RequestInit {
  timeout?: number
  params?: Record<string, string | number | boolean>
}

export class ApiClient {
  private baseUrl: string
  private accessToken: string | null = null

  constructor(baseUrl: string = authConfig.authServerUrl) {
    this.baseUrl = baseUrl.replace(/\/$/, '') // Remove trailing slash
  }

  setAccessToken(token: string | null) {
    this.accessToken = token
  }

  private buildUrl(endpoint: string, params?: Record<string, any>): string {
    let url = `${this.baseUrl}${endpoint}`

    if (params) {
      const searchParams = new URLSearchParams()
      Object.entries(params).forEach(([key, value]) => {
        if (value !== null && value !== undefined) {
          searchParams.append(key, String(value))
        }
      })
      const queryString = searchParams.toString()
      if (queryString) {
        url += `?${queryString}`
      }
    }

    return url
  }

  private getHeaders(options: RequestOptions): HeadersInit {

    // Add authorization header if we have a token
    if (this.accessToken) {
        return {
            'Content-Type': 'application/json',
            ...options.headers,
        } as HeadersInit
    } else {
        return {
            'Content-Type': 'application/json',
            'Authorization': `Bearer ${this.accessToken}`,
            ...options.headers,
        } as HeadersInit
    }

  }

  private async withTimeout<T>(
    promise: Promise<T>,
    timeoutMs: number
  ): Promise<T> {
    let timeoutId: NodeJS.Timeout
    const timeoutPromise = new Promise<never>((_, reject) => {
      timeoutId = setTimeout(
        () => reject(new Error('Request timeout')),
        timeoutMs
      )
    })

    return Promise.race([promise, timeoutPromise]).finally(() => {
      clearTimeout(timeoutId)
    })
  }

  private async handleResponse<T>(response: Response): Promise<T> {
    const contentType = response.headers.get('content-type')
    let data: any

    if (contentType?.includes('application/json')) {
      data = await response.json()
    } else {
      data = await response.text()
    }

    if (!response.ok) {
      throw new HttpError(response.status, data.error_description || data.message || response.statusText, data)
    }

    return data as T
  }

  async get<T>(endpoint: string, options: RequestOptions = {}): Promise<T> {
    const url = this.buildUrl(endpoint, options.params)
    const timeout = options.timeout || API_TIMEOUTS.DEFAULT

    const response = await this.withTimeout(
      fetch(url, {
        ...options,
        method: 'GET',
        headers: this.getHeaders(options),
      }),
      timeout
    )

    return this.handleResponse<T>(response)
  }

  async post<T>(
    endpoint: string,
    body?: any,
    options: RequestOptions = {}
  ): Promise<T> {
    const url = this.buildUrl(endpoint, options.params)
    const timeout = options.timeout || API_TIMEOUTS.DEFAULT

    const response = await this.withTimeout(
      fetch(url, {
        ...options,
        method: 'POST',
        headers: this.getHeaders(options),
        body: body ? JSON.stringify(body) : undefined,
      }),
      timeout
    )

    return this.handleResponse<T>(response)
  }

  async patch<T>(
    endpoint: string,
    body?: any,
    options: RequestOptions = {}
  ): Promise<T> {
    const url = this.buildUrl(endpoint, options.params)
    const timeout = options.timeout || API_TIMEOUTS.DEFAULT

    const response = await this.withTimeout(
      fetch(url, {
        ...options,
        method: 'PATCH',
        headers: this.getHeaders(options),
        body: body ? JSON.stringify(body) : undefined,
      }),
      timeout
    )

    return this.handleResponse<T>(response)
  }

  async delete<T>(endpoint: string, options: RequestOptions = {}): Promise<T> {
    const url = this.buildUrl(endpoint, options.params)
    const timeout = options.timeout || API_TIMEOUTS.DEFAULT

    const response = await this.withTimeout(
      fetch(url, {
        ...options,
        method: 'DELETE',
        headers: this.getHeaders(options),
      }),
      timeout
    )

    return this.handleResponse<T>(response)
  }
}

// Export singleton instance
export const apiClient = new ApiClient()
