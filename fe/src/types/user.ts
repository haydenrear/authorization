export interface UserInfo {
  sub: string
  email: string
  username: string
  email_verified: boolean
  updated_at?: number
}

export interface UserUpdateRequest {
  email?: string
  username?: string
}

export interface UserUpdateResponse extends UserInfo {}
