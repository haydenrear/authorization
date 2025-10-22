import {apiClient} from "./apiClient";
import {authConfig} from "@/config/authConfig";
import {GetTokensResponse, Token, TokenCreateRequest, TokenResponse} from "@/types/token";
import {OAuth2RevokeRequest} from "@/types/oauth";
import {decode, JwtPayload} from "jsonwebtoken"
import {authService} from "@/services/authService";

class JwtService {
    /**
     * Retrieve JWT token from URL query parameter
     * @param paramName The query parameter name (default: 'token')
     * @returns The JWT token or null if not found
     */
    getJwtFromQueryParam(paramName: string = "token"): string | null {
        console.log("Retrieving token from query parameter.")
        if (typeof window === "undefined") return null;

        const params = new URLSearchParams(window.location.search);
        const token = params.get(paramName);
        console.log("Found token", token)

        return token;
    }

    /**
     * Validate JWT token by decoding it
     * @param token The JWT token to validate
     * @returns True if the token is valid and not expired, false otherwise
     */
    isJwtValid(token: string): boolean {
        try {
            const parts = token.split(".");
            if (parts.length !== 3) {
                console.log("JWT did not contain three parts", parts.length)
                return false;
            }
            const payload = decode(token);

            if (payload === null) {
                return false;
            }

            const jwt = payload as JwtPayload;


            if (jwt.exp) {
                const expirationTime = jwt.exp * 1000;
                if (Date.now() >= expirationTime) {
                    console.log("Expiration time", expirationTime, "was before", Date.now())
                    return false;
                }
            }

            return true;
        } catch (error) {
            console.error("Failed to validate JWT:", error);
            return false;
        }
    }

    /**
     * Decode JWT token to extract payload
     * @param token The JWT token to decode
     * @returns The decoded payload or null if invalid
     */
    decodeJwt(token: string): JwtPayload | null | string | undefined {
        try {
            const parts = token.split(".");
            if (parts.length !== 3) {
                return null;
            }

            const payload = decode(token);

            const jwt = payload as JwtPayload;

            return jwt;

        } catch (error) {
            console.error("Failed to decode JWT:", error);
            return null;
        }
    }

    /**
     * Get expiration time from JWT token
     * @param token The JWT token
     * @returns The expiration time in seconds, or null if invalid
     */
    getJwtExpiration(token: string): number | null | undefined {
        const payload = this.decodeJwt(token);
        return (payload as JwtPayload)?.exp
    }

    getTokenFromParam(): undefined | null | string {
        const accessToken = authService.getAccessToken();

        if (accessToken && this.isJwtValid(accessToken)) {
            return accessToken
        }

        const jwt = this.getJwtFromQueryParam();

        if (jwt) {
            return jwt as string
        }

    }

    async createToken(request: TokenCreateRequest): Promise<TokenResponse> {
        try {

            const accessToken = authService.getAccessToken();

            if (accessToken) {
                return {
                    token_type: "bearer",
                    access_token: accessToken,
                    expires_in: authService.expiryTime()!!
                }
            } else {
                const jwt = this.getJwtFromQueryParam();
                if (jwt) {
                    console.log("Setting jwt from query parameter.")
                    if (this.isJwtValid(jwt as string)) {
                        authService.setUserAccessToken(jwt as string)
                        return await this.createToken(request);
                    }
                }
            }


            const tokenRequest: Record<string, any> = {
                grant_type: request.grant_type,
                scope: request.scope || "api:read api:write",
            };

            // Add grant-type specific fields
            if (
                request.grant_type === "urn:ietf:params:oauth:grant-type:jwt-bearer"
            ) {
                tokenRequest.assertion =
                    request.assertion || (await this.getJwtAssertion());
            } else if (request.grant_type === "authorization_code") {
                if (!request.code) {
                    throw new Error(
                        "Authorization code is required for authorization_code grant",
                    );
                }
                tokenRequest.code = request.code;
                tokenRequest.redirect_uri = request.redirect_uri;
                tokenRequest.client_id = request.client_id || authConfig.client.id;
            }

            // Add optional fields
            if (request.client_secret) {
                tokenRequest.client_secret = request.client_secret;
            }
            if (request.name) {
                tokenRequest.name = request.name;
            }

            const response = await apiClient.post<TokenResponse>(
                authConfig.oauth2.tokenEndpoint,
                tokenRequest,
            );
            return response;
        } catch (error) {
            console.error("Failed to create token:", error);
            throw error;
        }
    }

    private async getJwtAssertion(): Promise<string> {
        // Retrieve the current JWT token from auth service
        // This token was obtained during the authorization_code flow
        const {authService} = await import("./authService");
        const token = await authService.getAccessToken();

        if (!token) {
            throw new Error("No JWT assertion available. Please log in first.");
        }

        return token;
    }

    async listTokens(): Promise<GetTokensResponse> {
        try {
            // This endpoint should exist on your auth server
            // It returns all JWT tokens/API keys for the current user
            const tokens = await apiClient.get<GetTokensResponse>(
                authConfig.api.tokensEndpoint,
            );
            return tokens;
        } catch (error) {
            console.error("Failed to list tokens:", error);
            throw error;
        }
    }

    async revokeToken(tokenJtiOrValue: string): Promise<void> {
        try {
            // Try the revocation endpoint first (for refresh tokens or direct revocation)
            await apiClient.post(authConfig.oauth2.revokeEndpoint, {
                token: tokenJtiOrValue,
                token_type_hint: "access_token",
            } as OAuth2RevokeRequest);
        } catch (error) {
            // If that fails, try the custom API endpoint
            try {
                await apiClient.post(
                    `${authConfig.api.tokensEndpoint}/${tokenJtiOrValue}/revoke`,
                );
            } catch (innerError) {
                console.error("Failed to revoke token:", innerError);
                throw innerError;
            }
        }
    }

    async getTokenInfo(jti: string): Promise<Token> {
        try {
            const token = await apiClient.get<Token>(
                `${authConfig.api.tokensEndpoint}/${jti}`,
            );
            return token;
        } catch (error) {
            console.error("Failed to get token info:", error);
            throw error;
        }
    }
}

export const jwtService = new JwtService();
