'use client'

import {AccessToken, Token} from '@/types/token'
import { TokenCopyButton } from './TokenCopyButton'
import { TokenRevokeButton } from './TokenRevokeButton'
import { formatTokenDate, isTokenExpired, getTimeUntilExpiry } from '@/utils/tokenUtils'

export interface TokenListProps {
  tokens: AccessToken[]
  onRevoke: (jti: string) => Promise<void>
}

export function TokenList({ tokens, onRevoke }: TokenListProps) {
  if (tokens.length === 0) {
    return (
      <div className="text-center py-12">
        <p className="text-gray-600 text-lg">No API keys yet.</p>
        <p className="text-gray-500">Create your first API key to get started.</p>
      </div>
    )
  }

  return (
    <div className="space-y-4">
      {tokens.map((token) => (
        <div
          key={token.token.tokenValue}
          className="bg-white border border-gray-200 rounded-lg p-6 hover:border-gray-300 transition-colors"
        >
          <div className="flex items-start justify-between gap-4">
            <div className="flex-1 min-w-0">
              <div className="flex items-center gap-3 mb-2">
                <h3 className="font-semibold text-gray-900 truncate">
                  {token.token.tokenType.value || 'Unnamed API Key'}
                </h3>
                {isTokenExpired(token.token) && (
                  <span className="px-2 py-1 bg-red-100 text-red-800 text-xs font-semibold rounded whitespace-nowrap">
                    Expired
                  </span>
                )}
              </div>

              <p className="text-sm text-gray-600 mb-3 font-mono break-all">
                {token.token.tokenValue}
              </p>

              <div className="grid grid-cols-2 gap-4 text-sm">
                <div>
                  <span className="text-gray-600">Created</span>
                  <p className="font-medium text-gray-900">
                    {formatTokenDate(token.token.issuedAt)}
                  </p>
                </div>
                <div>
                  <span className="text-gray-600">Expires in</span>
                  <p className="font-medium text-gray-900">
                    {getTimeUntilExpiry(token.token)}
                  </p>
                </div>
                {/*{token.last_used && (*/}
                {/*  <div>*/}
                {/*    <span className="text-gray-600">Last used</span>*/}
                {/*    <p className="font-medium text-gray-900">*/}
                {/*      {formatTokenDate(token.last_used)}*/}
                {/*    </p>*/}
                {/*  </div>*/}
                {/*)}*/}
                <div>
                  <span className="text-gray-600">Scopes</span>
                  <p className="font-medium text-gray-900 truncate">{token.token.scopes}</p>
                </div>
              </div>
            </div>

            <div className="flex gap-2 flex-shrink-0">
              <TokenCopyButton token={token.token.tokenValue} label="Copy ID" />
              <TokenRevokeButton
                tokenName={token.token.tokenType.value}
                onRevoke={() => onRevoke(token.token.tokenValue)}
              />
            </div>
          </div>
        </div>
      ))}
    </div>
  )
}
