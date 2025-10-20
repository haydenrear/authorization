export interface Token {
  jti: string;
  created_at: string;
  expires_at: string;
  scope: string;
  last_used?: string;
  name?: string;
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

export interface TokenResponse {
  access_token: string;
  token_type: string;
  expires_in: number;
  scope?: string;
}

export interface TokenRevokeRequest {
  token: string;
  type_hint?: string;
}
