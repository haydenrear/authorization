'use client'

import { UserProfile } from './UserProfile'
import { UserEditForm } from './UserEditForm'
import { LoadingSpinner } from '../common/LoadingSpinner'
import { MESSAGES } from '@/utils/constants'
import { SuccessAlert } from '../common/SuccessAlert'
import { UseUserInfoReturn } from '@/hooks/useUserInfo'
import { useState } from 'react'

export interface UserProfileSectionProps {
  userInfo: UseUserInfoReturn
}

export function UserProfileSection({ userInfo }: UserProfileSectionProps) {
  const [successMessage, setSuccessMessage] = useState<string | null>(null)

  if (!userInfo.user) {
    return <LoadingSpinner message="Loading profile..." />
  }

  const handleUpdateEmail = async (email: string) => {
    await userInfo.updateEmail(email)
    setSuccessMessage(MESSAGES.USER_UPDATE_SUCCESS)
  }

  const handleUpdateUsername = async (username: string) => {
    await userInfo.updateUsername(username)
    setSuccessMessage(MESSAGES.USER_UPDATE_SUCCESS)
  }

  return (
    <div>
      {successMessage && (
        <SuccessAlert
          message={successMessage}
          onDismiss={() => setSuccessMessage(null)}
        />
      )}

      <div className="grid gap-6">
        <UserProfile user={userInfo.user} />
        <UserEditForm
          initialEmail={userInfo.user.email}
          initialUsername={userInfo.user.username}
          onUpdateEmail={handleUpdateEmail}
          onUpdateUsername={handleUpdateUsername}
          isLoading={userInfo.isLoading}
        />
      </div>
    </div>
  )
}
