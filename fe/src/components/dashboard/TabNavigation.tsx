'use client'

import { TAB_IDS } from '@/utils/constants'

export interface TabNavigationProps {
  activeTab: string
  setActive: (tabId: string) => void
}

const tabs = [
  { id: TAB_IDS.PROFILE, label: 'Profile' },
  { id: TAB_IDS.TOKENS, label: 'API Keys' },
  { id: TAB_IDS.CREDITS, label: 'Credits' },
]

export function TabNavigation({ activeTab, setActive }: TabNavigationProps) {
  return (
    <div className="border-b border-gray-200">
      <nav className="flex gap-8 px-6">
        {tabs.map((tab) => (
          <button
            key={tab.id}
            onClick={() => setActive(tab.id)}
            className={`py-4 px-1 border-b-2 font-medium text-sm transition-colors ${
              activeTab === tab.id
                ? 'border-blue-500 text-blue-600'
                : 'border-transparent text-gray-600 hover:text-gray-900 hover:border-gray-300'
            }`}
          >
            {tab.label}
          </button>
        ))}
      </nav>
    </div>
  )
}
