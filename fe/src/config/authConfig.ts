// Configuration for the authorization server
export const authConfig = {
  // Base URL of your authorization server
  authServerUrl: process.env.NEXT_PUBLIC_AUTH_SERVER_URL || 'http://localhost:8080',

  // OAuth2 endpoints
  oauth2: {
    tokenEndpoint: '/oauth2/token',
    revokeEndpoint: '/oauth2/revoke',
    userinfoEndpoint: '/userinfo',
  },

  // Custom API endpoints (if your auth server provides them)
  api: {
    tokensEndpoint: '/api/user/tokens',
    creditsEndpoint: '/api/user/credits',
    stripeCheckoutEndpoint: '/api/stripe/checkout',
  },

  // Client credentials (for token creation)
  // These should ideally come from environment variables in production
  client: {
    id: process.env.NEXT_PUBLIC_CLIENT_ID || '',
    secret: process.env.CLIENT_SECRET || '', // Keep secret server-side
  },

  // Stripe configuration
  stripe: {
    publishableKey: process.env.NEXT_PUBLIC_STRIPE_KEY || '',
  },
}
