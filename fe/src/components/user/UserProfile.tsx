'use client'

import { UserInfo } from '@/types/user'

export interface UserProfileProps {
  user: UserInfo
}

export function UserProfile({ user }: UserProfileProps) {
  return (
    <div className="bg-white rounded-lg border border-gray-200 p-6 mb-6">
      <h2 className="text-xl font-semibold text-gray-900 mb-4">User Information</h2>

      <div className="space-y-4">
        <div>
          <label className="block text-sm font-medium text-gray-700 mb-1">
            User ID
          </label>
          <p className="text-gray-900 font-mono text-sm break-all">{user.sub}</p>
        </div>

        <div>
          <label className="block text-sm font-medium text-gray-700 mb-1">
            Email
          </label>
          <p className="text-gray-900">{user.email}</p>
          {user.email_verified && (
            <span className="inline-block mt-2 px-2 py-1 bg-green-100 text-green-800 text-xs font-semibold rounded">
              Verified
            </span>
          )}
        </div>

        <div>
          <label className="block text-sm font-medium text-gray-700 mb-1">
            Username
          </label>
          <p className="text-gray-900">{user.username}</p>
        </div>

        {user.updated_at && (
          <div>
            <label className="block text-sm font-medium text-gray-700 mb-1">
              Last Updated
            </label>
            <p className="text-gray-600 text-sm">
              {new Date(user.updated_at * 1000).toLocaleString()}
            </p>
          </div>
        )}
      </div>
    </div>
  )
}
