/** Explicit single-operator integration with DSH 0.2's browser admission. */
import type { ConnectionTrustRequest, HostConnectionHandle } from '@deepseek-ai/dsh-client-connection'

/** Preview releases renamed operator to browserPeer and added its lifetime signal. */
interface PeerConnection {
  admit?: (request: ConnectionTrustRequest) => { rejection: 401 | 403 } | { peer: unknown }
  browserPeer?: { readonly signal?: AbortSignal }
  operator?: { readonly signal?: AbortSignal }
}

/** DSH 0.2.1 admits a live Peer for HTTP and socket transports. */
function installPeerAdmission(connection: HostConnectionHandle, authenticated: (cookie: string | undefined) => boolean): (() => void) | undefined {
  const peerConnection = connection as unknown as PeerConnection
  // Preserve the method identity and its receiver for restoration.
  const original = peerConnection.admit
  const peer = peerConnection.browserPeer ?? peerConnection.operator
  if (original === undefined || peer === undefined) return undefined
  const admit: typeof original = request => {
    const result = original.call(connection, request)
    if ('rejection' in result && result.rejection === 401 && peer.signal?.aborted !== true && authenticated(cookieFrom(request.headers))) return { peer }
    return result
  }
  peerConnection.admit = admit
  return () => { if (peerConnection.admit === admit) peerConnection.admit = original }
}

/** Bridge only installations whose authenticated users may act as the native operator. */
export function installNativeAuthBridge(
  connection: HostConnectionHandle,
  authenticated: (cookie: string | undefined) => boolean,
): () => void {
  const restoreAdmission = installPeerAdmission(connection, authenticated)
  // eslint-disable-next-line @typescript-eslint/unbound-method -- Preserve the original method identity; invoke it with call(connection).
  const originalRejection = connection.requestRejection
  // eslint-disable-next-line @typescript-eslint/unbound-method -- Preserve the original method identity; invoke it with call(connection).
  const originalIndex = connection.authorizeIndex
  const rejection: typeof originalRejection = request => {
    const result = originalRejection.call(connection, request)
    return restoreAdmission === undefined && result === 401 && authenticated(cookieFrom(request.headers)) ? undefined : result
  }
  const index: typeof originalIndex = (request, response) => {
    // authorizeIndex may end the response; check the unchanged fence before calling it.
    const result = originalRejection.call(connection, request)
    const allowed = restoreAdmission === undefined ? result !== 403 : result === undefined
    if (allowed && authenticated(cookieFrom(request.headers))) return true
    return originalIndex.call(connection, request, response)
  }
  connection.requestRejection = rejection
  connection.authorizeIndex = index
  return () => {
    restoreAdmission?.()
    if (connection.requestRejection === rejection) connection.requestRejection = originalRejection
    if (connection.authorizeIndex === index) connection.authorizeIndex = originalIndex
  }
}

function cookieFrom(headers: ConnectionTrustRequest['headers']): string | undefined {
  const value = headers instanceof Headers ? headers.get('cookie') : Object.entries(headers).find(([key]) => key.toLowerCase() === 'cookie')?.[1]
  return typeof value === 'string' ? value : undefined
}
