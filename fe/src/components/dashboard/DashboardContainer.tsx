'use client'

import { useState, useEffect } from 'react'
import { TabNavigation } from './TabNavigation'
import { UserProfileSection } from '../user/UserProfileSection'
import { TokensSection } from '../tokens/TokensSection'
import { CreditsSection } from '../credits/CreditsSection'
import { LoadingSpinner } from '../common/LoadingSpinner'
import { ErrorAlert } from '../common/ErrorAlert'
import { useUserInfo } from '@/hooks/useUserInfo'
import { useTokens } from '@/hooks/useTokens'
import { useCredits } from '@/hooks/useCredits'
import { useAuth } from '@/hooks/useAuth'
import { TAB_IDS } from '@/utils/constants'

export function DashboardContainer() {
  const [activeTab, setActiveTab] = useState(TAB_IDS.PROFILE)
  const [isInitializing, setIsInitializing] = useState(true)

  const auth = useAuth()
  const userInfo = useUserInfo()
  const tokens = useTokens()
  const credits = useCredits()

  useEffect(() => {
    const initialize = async () => {
      try {
        // Ensure we have a valid token
        if (!auth.isTokenValid()) {
          await auth.getToken()
        }

        // Fetch initial data
        await Promise.all([
          userInfo.fetchUser(),
          tokens.fetchTokens(),
          credits.fetchCredits(),
        ])
      } catch (error) {
        console.error('Failed to initialize dashboard:', error)
      } finally {
        setIsInitializing(false)
      }
    }

    initialize()
  }, [])

  if (isInitializing) {
    return <LoadingSpinner fullScreen message="Loading dashboard..." />
  }

  // @ts-ignore
    // @ts-ignore
    return (
    <div className="min-h-screen bg-gray-50">
      <div className="max-w-6xl mx-auto">
        {/* Header */}
        <div className="bg-white border-b border-gray-200 px-6 py-8">
          <h1 className="text-3xl font-bold text-gray-900">Dashboard</h1>
          <p className="text-gray-600 mt-2">Manage your account, API keys, and credits</p>
        </div>

        {/* Global errors */}
        <div className="px-6 pt-6">
          {(userInfo.error || tokens.error || credits.error) && (
            <ErrorAlert
              error={userInfo.error || tokens.error || credits.error}
              onDismiss={() => {
                userInfo.clearError()
                tokens.clearError()
                credits.clearError()
              }}
            />
          )}
        </div>

        {/* @ts-ignore */}
        <TabNavigation activeTab={activeTab} setActive={setActiveTab} />

        {/* Content */}
        <div className="px-6 py-8">
            {/* @ts-ignore */}
          {activeTab === TAB_IDS.PROFILE && (
            <UserProfileSection userInfo={userInfo} />
          )}
            {/* @ts-ignore */}
          {activeTab === TAB_IDS.TOKENS && (
            <TokensSection tokens={tokens} />
          )}
            {/* @ts-ignore */}
          {activeTab === TAB_IDS.CREDITS && (
            <CreditsSection credits={credits} />
          )}
        </div>
      </div>
    </div>
  )
}
