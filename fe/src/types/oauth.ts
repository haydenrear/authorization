export interface OAuth2TokenRequest {
  grant_type: string
  scope?: string
  client_id?: string
  client_secret?: string
}

export interface OAuth2RevokeRequest {
  token: string
  client_id?: string
  client_secret?: string
  token_type_hint?: string
}

export interface OAuth2Error {
  error: string
  error_description?: string
  error_uri?: string
}
