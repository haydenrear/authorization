import { apiClient } from "./apiClient";
import { authConfig } from "@/config/authConfig";
import { TokenResponse } from "@/types/token";
import { OAuth2RevokeRequest } from "@/types/oauth";
import { TOKEN_STORAGE_KEY } from "@/utils/constants";
import { jwtService } from "./jwtService";

class AuthService {
  private accessToken: string | null = null;
  private tokenExpiryTime: number | null = null;

  constructor() {
    this.loadTokenFromStorage();
  }

  private loadTokenFromStorage() {
    if (typeof window === "undefined") return;

    const stored = localStorage.getItem(TOKEN_STORAGE_KEY);
    if (stored) {
      try {
        const { token, expiry } = JSON.parse(stored);
        this.accessToken = token;
        this.tokenExpiryTime = expiry;
      } catch (e) {
        console.error("Failed to load token from storage");
        this.clearToken();
      }
    }
  }

  /**
   * Check for JWT token in URL query parameter and validate it
   * @param paramName The query parameter name (default: 'token')
   * @returns True if a valid JWT was found and stored, false otherwise
   */
  private loadTokenFromQueryParam(paramName: string = "token"): boolean {
    if (typeof window === "undefined") return false;

    const queryToken = jwtService.getJwtFromQueryParam(paramName);
    if (!queryToken)
        return false;

    // Validate the token
    if (!jwtService.isJwtValid(queryToken)) {
      console.error("Invalid or expired JWT token in query parameter");
      return false;
    }

    // Get expiration time from token
    const expirationTime = jwtService.getJwtExpiration(queryToken);
    if (!expirationTime) {
      console.error("Could not extract expiration from JWT token");
      return false;
    }

    // Convert expiration from seconds to milliseconds and store
    const expiresIn = Math.floor((expirationTime * 1000 - Date.now()) / 1000);
    this.saveTokenToStorage(queryToken, expiresIn);

    // Clean up the URL by removing the token parameter
    this.cleanupQueryParam(paramName);

    return true;
  }

  /**
   * Remove the token query parameter from the URL
   */
  private cleanupQueryParam(paramName: string) {
    if (typeof window === "undefined") return;

    const params = new URLSearchParams(window.location.search);
    // if (params.has(paramName)) {
    //   params.delete(paramName);
    //   window.history.replaceState({}, document.title, newUrl);
    // }
  }

  private saveTokenToStorage(token: string, expiresIn: number) {
    if (typeof window === "undefined") return;

    const expiry = Date.now() + expiresIn * 1000;
    this.accessToken = token;
    this.tokenExpiryTime = expiry;
    localStorage.setItem(TOKEN_STORAGE_KEY, JSON.stringify({ token, expiry }));
    apiClient.setAccessToken(token);
  }

  public clearToken() {
    this.accessToken = null;
    this.tokenExpiryTime = null;
    if (typeof window !== "undefined") {
      localStorage.removeItem(TOKEN_STORAGE_KEY);
    }
    apiClient.setAccessToken(null);
  }

  isTokenExpired(): boolean {
    if (!this.tokenExpiryTime) return true;
    return Date.now() >= this.tokenExpiryTime - 60000; // 1 minute buffer
  }

  async getAccessToken(): Promise<string | null> {
    if (this.accessToken && !this.isTokenExpired()) {
      return this.accessToken;
    }

    if (this.loadTokenFromQueryParam()) {
        return this.accessToken;
    }

    if (this.isTokenExpired()) {
      this.clearToken();
    }

    return this.accessToken;
  }

  // Create a new client credentials token (API key)
  async createClientToken(scope?: string): Promise<TokenResponse> {
    const response = await apiClient.post<TokenResponse>(
      authConfig.oauth2.tokenEndpoint,
      {
        grant_type: "client_credentials",
        client_id: authConfig.client.id,
        scope: scope || "api:read api:write",
      },
      { headers: { "Content-Type": "application/x-www-form-urlencoded" } },
    );
    return response;
  }

  // Store the user's access token (typically from OIDC flow)
  setUserAccessToken(token: string, expiresIn: number = 3600) {
    this.saveTokenToStorage(token, expiresIn);
  }

  // Revoke the current access token
  async revokeAccessToken(token?: string): Promise<void> {
    const tokenToRevoke = token || this.accessToken;
    if (!tokenToRevoke) {
      throw new Error("No token to revoke");
    }

    try {
      await apiClient.post(authConfig.oauth2.revokeEndpoint, {
        token: tokenToRevoke,
        client_id: authConfig.client.id,
      } as OAuth2RevokeRequest);
    } finally {
      // Clear even if revocation fails
      this.clearToken();
    }
  }

  // Revoke a specific token by JTI
  async revokeTokenByJti(jti: string): Promise<void> {
    // This assumes your auth server has an endpoint for this
    // Otherwise, you may need to implement this differently
    await apiClient.post(`/api/user/tokens/${jti}/revoke`);
  }
}

export const authService = new AuthService();
