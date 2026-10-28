import type { ConnectionTrustRequest } from '@deepseek-ai/dsh-client-connection'
import type { IncomingMessage, ServerResponse } from 'node:http'
import { authenticatedEntryPage } from './html.js'
import { redirect, safeReturnTarget, writeHtml } from './http.js'
import type { UiPreferences } from './preferences.js'

interface BrowserEntryRequest {
  readonly headers: ConnectionTrustRequest['headers']
  readonly method?: string | undefined
}

/** Only a top-level read navigation needs a document to reset Fetch Metadata. */
export function isCrossSiteNavigation(request: BrowserEntryRequest): boolean {
  const header = (name: string) => request.headers instanceof Headers
    ? request.headers.get(name)
    : request.headers[name]
  return request.method === 'GET'
    && header('sec-fetch-site') === 'cross-site'
    && header('sec-fetch-mode') === 'navigate'
    && header('sec-fetch-dest') === 'document'
}

/** Preserve a safe application target through the ordinary login route. */
export function browserEntryTarget(basePath: string, returnTo?: string): string {
  return `${basePath}/login?returnTo=${encodeURIComponent(safeReturnTarget(returnTo))}`
}

interface AuthenticatedNavigation {
  readonly basePath: string
  readonly returnTo: string
  readonly preferences: UiPreferences
  readonly headers: Record<string, string | string[]>
}

/** A committed document prevents a cross-site redirect chain reaching native admission. */
export function continueAuthenticatedNavigation(req: IncomingMessage, res: ServerResponse, options: AuthenticatedNavigation): void {
  if (isCrossSiteNavigation(req)) {
    const target = browserEntryTarget(options.basePath, options.returnTo)
    writeHtml(res, 200, authenticatedEntryPage(target, options.preferences), options.headers)
  } else {
    redirect(res, options.returnTo, options.headers)
  }
}
