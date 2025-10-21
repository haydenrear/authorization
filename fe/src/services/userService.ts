import { apiClient } from './apiClient'
import { authConfig } from '@/config/authConfig'
import { UserInfo, UserUpdateRequest, UserUpdateResponse } from '@/types/user'
import { USER_STORAGE_KEY } from '@/utils/constants'

class UserService {
  private userInfoCache: UserInfo | null = null

  async fetchUserInfo(): Promise<UserInfo> {
    try {
      const userInfo = await apiClient.get<UserInfo>(
        authConfig.oauth2.userinfoEndpoint)
      this.userInfoCache = userInfo
      this.saveUserToStorage(userInfo)
      return userInfo
    } catch (error) {
      console.error('Failed to fetch user info:', error)
      throw error
    }
  }

  getCachedUserInfo(): UserInfo | null {
    if (this.userInfoCache) {
      return this.userInfoCache
    }

    // Try to load from storage
    if (typeof window !== 'undefined') {
      const stored = localStorage.getItem(USER_STORAGE_KEY)
      if (stored) {
        try {
          this.userInfoCache = JSON.parse(stored)
          return this.userInfoCache
        } catch (e) {
          console.error('Failed to parse cached user info')
        }
      }
    }

    return null
  }

  private saveUserToStorage(userInfo: UserInfo) {
    if (typeof window === 'undefined') return
    localStorage.setItem(USER_STORAGE_KEY, JSON.stringify(userInfo))
  }

  clearUserCache() {
    this.userInfoCache = null
    if (typeof window !== 'undefined') {
      localStorage.removeItem(USER_STORAGE_KEY)
    }
  }

  async updateEmail(email: string): Promise<UserUpdateResponse> {
    try {
      const response = await apiClient.patch<UserUpdateResponse>(
        authConfig.oauth2.userinfoEndpoint,
        { email } as UserUpdateRequest
      )
      this.userInfoCache = response
      this.saveUserToStorage(response)
      return response
    } catch (error) {
      console.error('Failed to update email:', error)
      throw error
    }
  }

  async updateUsername(username: string): Promise<UserUpdateResponse> {
    try {
      const response = await apiClient.patch<UserUpdateResponse>(
        authConfig.oauth2.userinfoEndpoint,
        { username } as UserUpdateRequest
      )
      this.userInfoCache = response
      this.saveUserToStorage(response)
      return response
    } catch (error) {
      console.error('Failed to update username:', error)
      throw error
    }
  }
}

export const userService = new UserService()
