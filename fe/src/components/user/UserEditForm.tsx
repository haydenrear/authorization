'use client'

import { useState } from 'react'
import { LoadingSpinner } from '../common/LoadingSpinner'

export interface UserEditFormProps {
  initialEmail: string
  initialUsername: string
  onUpdateEmail: (email: string) => Promise<void>
  onUpdateUsername: (username: string) => Promise<void>
  isLoading?: boolean
}

export function UserEditForm({
  initialEmail,
  initialUsername,
  onUpdateEmail,
  onUpdateUsername,
  isLoading = false,
}: UserEditFormProps) {
  const [email, setEmail] = useState(initialEmail)
  const [username, setUsername] = useState(initialUsername)
  const [isUpdatingEmail, setIsUpdatingEmail] = useState(false)
  const [isUpdatingUsername, setIsUpdatingUsername] = useState(false)

  const handleUpdateEmail = async (e: React.FormEvent) => {
    e.preventDefault()
    if (email === initialEmail) return

    setIsUpdatingEmail(true)
    try {
      await onUpdateEmail(email)
    } catch (error) {
      // Error is handled by parent component
      setEmail(initialEmail)
    } finally {
      setIsUpdatingEmail(false)
    }
  }

  const handleUpdateUsername = async (e: React.FormEvent) => {
    e.preventDefault()
    if (username === initialUsername) return

    setIsUpdatingUsername(true)
    try {
      await onUpdateUsername(username)
    } catch (error) {
      // Error is handled by parent component
      setUsername(initialUsername)
    } finally {
      setIsUpdatingUsername(false)
    }
  }

  return (
    <div className="bg-white rounded-lg border border-gray-200 p-6 space-y-6">
      <h2 className="text-xl font-semibold text-gray-900">Update Profile</h2>

      {/* Email Update */}
      <form onSubmit={handleUpdateEmail} className="space-y-4">
        <div>
          <label htmlFor="email" className="block text-sm font-medium text-gray-700 mb-2">
            Email
          </label>
          <input
            id="email"
            type="email"
            value={email}
            onChange={(e) => setEmail(e.target.value)}
            disabled={isUpdatingEmail || isLoading}
            className="w-full px-4 py-2 border border-gray-300 rounded-lg focus:ring-blue-500 focus:border-blue-500 disabled:bg-gray-100 disabled:cursor-not-allowed"
          />
        </div>
        <button
          type="submit"
          disabled={email === initialEmail || isUpdatingEmail || isLoading}
          className="px-4 py-2 bg-blue-600 text-white rounded-lg hover:bg-blue-700 disabled:bg-gray-400 disabled:cursor-not-allowed flex items-center gap-2"
        >
          {isUpdatingEmail && <span className="w-4 h-4 border-2 border-white border-t-transparent rounded-full animate-spin" />}
          Update Email
        </button>
      </form>

      {/* Username Update */}
      <form onSubmit={handleUpdateUsername} className="space-y-4">
        <div>
          <label htmlFor="username" className="block text-sm font-medium text-gray-700 mb-2">
            Username
          </label>
          <input
            id="username"
            type="text"
            value={username}
            onChange={(e) => setUsername(e.target.value)}
            disabled={isUpdatingUsername || isLoading}
            className="w-full px-4 py-2 border border-gray-300 rounded-lg focus:ring-blue-500 focus:border-blue-500 disabled:bg-gray-100 disabled:cursor-not-allowed"
          />
        </div>
        <button
          type="submit"
          disabled={username === initialUsername || isUpdatingUsername || isLoading}
          className="px-4 py-2 bg-blue-600 text-white rounded-lg hover:bg-blue-700 disabled:bg-gray-400 disabled:cursor-not-allowed flex items-center gap-2"
        >
          {isUpdatingUsername && <span className="w-4 h-4 border-2 border-white border-t-transparent rounded-full animate-spin" />}
          Update Username
        </button>
      </form>
    </div>
  )
}
