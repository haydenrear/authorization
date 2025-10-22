export interface Token {
  tokenValue: string;
  issuedAt: string;
  expiresAt: string;
  tokenType: {
      value: string
  },
  scopes: Set<string>
}

export interface AccessToken {
    token: Token;
    metadata: Map<string, object>;
    active: boolean;
    expired: boolean;
    claims: Map<string, object>;
    invalidated: boolean;
    beforeUser: boolean;
}

export interface GetTokensResponse {
    token: [AccessToken],
    success: boolean,
    error: string
}

export interface TokenResponse {
    access_token: string;
    token_type: string;
    expires_in: number;
    scope?: string;
}

export interface TokenCreateRequest {
  grant_type:
    | "authorization_code"
    | "urn:ietf:params:oauth:grant-type:jwt-bearer";
  scope?: string;
  name?: string;
  assertion?: string; // JWT assertion for jwt-bearer grant
  code?: string; // Authorization code for authorization_code grant
  redirect_uri?: string; // Redirect URI for authorization_code grant
  client_id?: string;
  client_secret?: string;
}


export interface TokenRevokeRequest {
  token: string;
  type_hint?: string;
}

