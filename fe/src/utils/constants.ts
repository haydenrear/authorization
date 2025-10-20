export const API_TIMEOUTS = {
  DEFAULT: 10000, // 10 seconds
  LONG: 30000, // 30 seconds
} as const

export const SCOPES = {
  PROFILE: 'profile',
  EMAIL: 'email',
  API_READ: 'api:read',
  API_WRITE: 'api:write',
  CREDITS: 'credits',
} as const

export const TOKEN_STORAGE_KEY = 'auth_token'
export const USER_STORAGE_KEY = 'user_info'

export const MESSAGES = {
  // User updates
  USER_UPDATE_SUCCESS: 'Profile updated successfully',
  USER_UPDATE_ERROR: 'Failed to update profile',

  // Token operations
  TOKEN_CREATED: 'API key created successfully',
  TOKEN_REVOKED: 'API key revoked successfully',
  TOKEN_COPIED: 'API key copied to clipboard',
  TOKEN_COPY_ERROR: 'Failed to copy to clipboard',
  TOKEN_CREATE_ERROR: 'Failed to create API key',
  TOKEN_REVOKE_ERROR: 'Failed to revoke API key',

  // Credits
  CREDITS_FETCH_ERROR: 'Failed to load credits',
  CHECKOUT_ERROR: 'Failed to initiate checkout',

  // General
  LOADING: 'Loading...',
  ERROR: 'An error occurred',
  CONFIRM_ACTION: 'Are you sure?',
} as const

export const TAB_IDS = {
  PROFILE: 'profile',
  TOKENS: 'tokens',
  CREDITS: 'credits',
} as const
