import { Token } from '@/types/token'

export function formatTokenDate(dateString: string): string {
  const date = new Date(dateString)
  return date.toLocaleDateString('en-US', {
    month: 'short',
    day: 'numeric',
    year: 'numeric',
    hour: '2-digit',
    minute: '2-digit',
  })
}

export function isTokenExpired(token: Token): boolean {
  const expiresAt = new Date(token.expires_at)
  return expiresAt < new Date()
}

export function getTimeUntilExpiry(token: Token): string {
  const expiresAt = new Date(token.expires_at)
  const now = new Date()
  const diffMs = expiresAt.getTime() - now.getTime()

  if (diffMs < 0) {
    return 'Expired'
  }

  const diffDays = Math.floor(diffMs / (1000 * 60 * 60 * 24))
  const diffHours = Math.floor((diffMs / (1000 * 60 * 60)) % 24)
  const diffMins = Math.floor((diffMs / (1000 * 60)) % 60)

  if (diffDays > 0) {
    return `${diffDays}d ${diffHours}h`
  } else if (diffHours > 0) {
    return `${diffHours}h ${diffMins}m`
  } else {
    return `${diffMins}m`
  }
}

export function maskToken(token: string, visibleChars: number = 8): string {
  if (token.length <= visibleChars) {
    return token
  }
  const visible = token.slice(0, visibleChars)
  const masked = '*'.repeat(token.length - visibleChars)
  return `${visible}${masked}`
}

export function sortTokensByDate(tokens: Token[], order: 'asc' | 'desc' = 'desc'): Token[] {
  return [...tokens].sort((a, b) => {
    const dateA = new Date(a.created_at).getTime()
    const dateB = new Date(b.created_at).getTime()
    return order === 'desc' ? dateB - dateA : dateA - dateB
  })
}
