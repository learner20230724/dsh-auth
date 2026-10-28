import { describe, expect, it, vi } from 'vitest'
import type { ConnectionTrustRequest, HostConnectionHandle } from '@deepseek-ai/dsh-client-connection'
import { installNativeAuthBridge } from '../src/native-auth.js'

function fixture(nativeStatus: 401 | 403 | undefined, valid = true) {
  const requestRejection = vi.fn(() => nativeStatus)
  const authorizeIndex = vi.fn(() => false)
  const connection = { requestRejection, authorizeIndex } as unknown as HostConnectionHandle
  const authenticated = vi.fn(() => valid)
  const dispose = installNativeAuthBridge(connection, authenticated)
  return { connection, requestRejection, authorizeIndex, authenticated, dispose }
}

describe('explicit native operator bridge', () => {
  it('preserves 0.2.0 index admission when an operator and admit method also exist', () => {
    const connection = {
      operator: {},
      requestRejection: vi.fn<(request: ConnectionTrustRequest) => 401 | undefined>(() => 401),
      admit(request: ConnectionTrustRequest) {
        const rejection = this.requestRejection(request)
        return rejection === undefined ? { peer: this.operator } : { rejection }
      },
      authorizeIndex: vi.fn(() => false),
    }
    const handle = connection as unknown as HostConnectionHandle
    const dispose = installNativeAuthBridge(handle, () => true)
    expect(handle.authorizeIndex({ headers: {}, method: 'GET', url: '/' }, {} as never)).toBe(true)
    dispose()
  })

  it('admits the live browser Peer for 0.2.1 HTTP and socket transports, preserving native denials and revocation', () => {
    const lifetime = new AbortController()
    const browserPeer = { signal: lifetime.signal }
    let accepted = true
    const nativeAdmission = vi.fn<(request: ConnectionTrustRequest) => { rejection: number } | { peer: unknown }>(() => ({ rejection: 401 }))
    const connection = {
      browserPeer,
      admit: nativeAdmission,
      requestRejection(request: ConnectionTrustRequest) {
        const result = this.admit(request)
        return 'rejection' in result ? result.rejection : undefined
      },
      authorizeIndex: vi.fn(() => false),
    }
    const dispose = installNativeAuthBridge(connection as unknown as HostConnectionHandle, () => accepted)
    const request = { headers: { cookie: 'signed-session' } }
    expect(connection.admit(request)).toEqual({ peer: browserPeer })
    expect(connection.requestRejection(request)).toBeUndefined()
    accepted = false
    expect(connection.admit(request)).toEqual({ rejection: 401 })
    accepted = true
    nativeAdmission.mockReturnValue({ rejection: 403 })
    expect(connection.admit(request)).toEqual({ rejection: 403 })
    const apiPeer = { id: 'existing-api-peer' }
    nativeAdmission.mockReturnValue({ peer: apiPeer })
    expect(connection.admit(request)).toEqual({ peer: apiPeer })
    nativeAdmission.mockReturnValue({ rejection: 401 })
    lifetime.abort()
    expect(connection.admit(request)).toEqual({ rejection: 401 })
    expect(connection.requestRejection(request)).toBe(401)
    dispose()
    expect(connection.admit).toBe(nativeAdmission)
  })

  it.each([{ cookie: 'signed-session' }, new Headers({ Cookie: 'signed-session' })])('accepts a verified session with Node or Fetch headers', headers => {
    const f = fixture(401)
    expect(f.connection.requestRejection({ headers })).toBeUndefined()
    expect(f.authenticated).toHaveBeenCalledWith('signed-session')
  })
  it('preserves the native Host and Origin rejection even with a valid session', () => {
    const f = fixture(403)
    expect(f.connection.requestRejection({ headers: {} })).toBe(403)
    expect(f.authenticated).not.toHaveBeenCalled()
  })
  it('denies invalid or revoked sessions and preserves existing native authentication', () => {
    const denied = fixture(401, false)
    expect(denied.connection.requestRejection({ headers: {} })).toBe(401)
    const native = fixture(undefined, false)
    expect(native.connection.requestRejection({ headers: {} })).toBeUndefined()
    expect(native.authenticated).not.toHaveBeenCalled()
  })
  it('allows index before the native method can end the response', () => {
    const f = fixture(401)
    const request = { headers: {}, method: 'GET', url: '/' }
    expect(f.connection.authorizeIndex(request, {} as never)).toBe(true)
    expect(f.authorizeIndex).not.toHaveBeenCalled()
    f.dispose()
    expect(f.connection.authorizeIndex(request, {} as never)).toBe(false)
  })
  it('delegates rejected index requests and restores only its own wrappers', () => {
    const f = fixture(403)
    expect(f.connection.authorizeIndex({ headers: {} }, {} as never)).toBe(false)
    expect(f.authorizeIndex).toHaveBeenCalledOnce()
    const replacement = () => 401 as const
    f.connection.requestRejection = replacement
    f.dispose()
    expect(Object.getOwnPropertyDescriptor(f.connection, 'requestRejection')?.value).toBe(replacement)
    expect(Object.getOwnPropertyDescriptor(f.connection, 'authorizeIndex')?.value).toBe(f.authorizeIndex)
  })

  it('marks authenticated cross-site documents for login re-entry without granting native admission', () => {
    const f = fixture(403)
    const writeHead = vi.fn()
    f.authorizeIndex.mockImplementationOnce((...args: unknown[]) => {
      const response = args[1] as { writeHead(status: number, headers: Record<string, string>): void }
      response.writeHead(403, { 'cache-control': 'no-store' })
      return false
    })
    const request = {
      method: 'GET', url: '/workspace',
      headers: { 'sec-fetch-site': 'cross-site', 'sec-fetch-mode': 'navigate', 'sec-fetch-dest': 'document' },
    }
    expect(f.connection.authorizeIndex(request, { writeHead, end: vi.fn() })).toBe(false)
    expect(writeHead).toHaveBeenCalledWith(403, { 'cache-control': 'no-store', 'x-dsh-auth-login': '/auth/login?returnTo=%2Fworkspace' })
    expect(f.authorizeIndex).toHaveBeenCalledOnce()
    expect(f.connection.requestRejection(request)).toBe(403)
  })
})
