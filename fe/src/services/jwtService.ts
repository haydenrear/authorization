import { apiClient } from './apiClient'
import { authConfig } from '@/config/authConfig'
import { Token, TokenCreateRequest, TokenResponse } from '@/types/token'
import { OAuth2RevokeRequest } from '@/types/oauth'

class JwtService {
  async createToken(request: TokenCreateRequest): Promise<TokenResponse> {
    try {
      // Build the token request based on grant type
      const tokenRequest: Record<string, any> = {
        grant_type: request.grant_type,
        scope: request.scope || 'api:read api:write',
      }

      // Add grant-type specific fields
      if (request.grant_type === 'urn:ietf:params:oauth:grant-type:jwt-bearer') {
        tokenRequest.assertion = request.assertion || await this.getJwtAssertion()
      } else if (request.grant_type === 'authorization_code') {
        if (!request.code) {
          throw new Error('Authorization code is required for authorization_code grant')
        }
        tokenRequest.code = request.code
        tokenRequest.redirect_uri = request.redirect_uri
        tokenRequest.client_id = request.client_id || authConfig.client.id
      }

      // Add optional fields
      if (request.client_secret) {
        tokenRequest.client_secret = request.client_secret
      }
      if (request.name) {
        tokenRequest.name = request.name
      }

      const response = await apiClient.post<TokenResponse>(
        authConfig.oauth2.tokenEndpoint,
        tokenRequest
      )
      return response
    } catch (error) {
      console.error('Failed to create token:', error)
      throw error
    }
  }

  private async getJwtAssertion(): Promise<string> {
    // Retrieve the current JWT token from auth service
    // This token was obtained during the authorization_code flow
    const { authService } = await import('./authService')
    const token = await authService.getAccessToken()

    if (!token) {
      throw new Error('No JWT assertion available. Please log in first.')
    }

    return token
  }

  async listTokens(): Promise<Token[]> {
    try {
      // This endpoint should exist on your auth server
      // It returns all JWT tokens/API keys for the current user
      const tokens = await apiClient.get<Token[]>(
        authConfig.api.tokensEndpoint
      )
      return tokens
    } catch (error) {
      console.error('Failed to list tokens:', error)
      throw error
    }
  }

  async revokeToken(tokenJtiOrValue: string): Promise<void> {
    try {
      // Try the revocation endpoint first (for refresh tokens or direct revocation)
      await apiClient.post(authConfig.oauth2.revokeEndpoint, {
        token: tokenJtiOrValue,
        token_type_hint: 'access_token',
      } as OAuth2RevokeRequest)
    } catch (error) {
      // If that fails, try the custom API endpoint
      try {
        await apiClient.post(`${authConfig.api.tokensEndpoint}/${tokenJtiOrValue}/revoke`)
      } catch (innerError) {
        console.error('Failed to revoke token:', innerError)
        throw innerError
      }
    }
  }

  async getTokenInfo(jti: string): Promise<Token> {
    try {
      const token = await apiClient.get<Token>(
        `${authConfig.api.tokensEndpoint}/${jti}`
      )
      return token
    } catch (error) {
      console.error('Failed to get token info:', error)
      throw error
    }
  }
}

export const jwtService = new JwtService()
