import { once } from 'node:events'
import http from 'node:http'
import { afterAll, beforeAll, describe, expect, it } from 'vitest'
import { CSRF_COOKIE, SESSION_COOKIE } from '../src/cookies.js'
import { cookiePair, hiddenValue, proxyHeaders, startTestServer, testConfig, testCredentials } from './helpers.js'
import type { TestCredentials, TestServer } from './helpers.js'

const navigation = {
  'sec-fetch-site': 'cross-site',
  'sec-fetch-mode': 'navigate',
  'sec-fetch-dest': 'document',
}

let credentials: TestCredentials
let running: TestServer

beforeAll(async () => {
  credentials = await testCredentials()
  running = await startTestServer(testConfig(credentials))
}, 30_000)

afterAll(async () => {
  running.server.close()
  await once(running.server, 'close')
})

async function signIn(): Promise<string> {
  const page = await fetch(`${running.baseUrl}/auth/login`)
  const html = await page.text()
  const result = await fetch(`${running.baseUrl}/auth/login`, {
    method: 'POST', redirect: 'manual',
    headers: { ...proxyHeaders(), cookie: cookiePair(page.headers, CSRF_COOKIE) },
    body: new URLSearchParams({ csrf: hiddenValue(html, 'csrf'), username: 'test-account', password: credentials.password }),
  })
  expect(result.status).toBe(303)
  return cookiePair(result.headers, SESSION_COOKIE)
}

// Undici supplies its own Sec-Fetch-Mode; use HTTP for exact browser metadata.
function navigate(url: string, cookie: string): Promise<Response> {
  return new Promise((resolve, reject) => {
    const request = http.get(url, { headers: { cookie, ...navigation } }, response => {
      const chunks: Buffer[] = []
      response.on('data', (chunk: Buffer) => { chunks.push(chunk) })
      response.on('end', () => {
        const headers = new Headers()
        for (const [name, values] of Object.entries(response.headers)) {
          for (const value of Array.isArray(values) ? values : values === undefined ? [] : [values]) headers.append(name, value)
        }
        resolve(new Response(Buffer.concat(chunks), { status: response.statusCode ?? 500, headers }))
      })
    })
    request.on('error', reject)
    request.setTimeout(5000, () => { request.destroy(new Error('browser navigation timed out')) })
  })
}

describe('authenticated browser entry', () => {
  it('loads a same-origin document before redirecting an already signed-in cross-site visitor', async () => {
    const cookie = await signIn()
    const response = await navigate(`${running.baseUrl}/auth/login?returnTo=%2Fworkspace%3Ftab%3Drecent`, cookie)
    expect(response.status).toBe(200)
    expect(response.headers.get('cache-control')).toContain('no-store')
    expect(response.headers.get('content-security-policy')).toContain("default-src 'none'")
    const html = await response.text()
    const target = '/auth/login?returnTo=%2Fworkspace%3Ftab%3Drecent'
    expect(html).toContain(`<meta http-equiv="refresh" content="0;url=${target}">`)
    expect(html).toContain(`href="${target}"`)
    expect(html).not.toContain(credentials.password)
    const continuation = await fetch(`${running.baseUrl}${target}`, {
      redirect: 'manual', headers: { cookie, ...navigation, 'sec-fetch-site': 'same-origin' },
    })
    expect(continuation.status).toBe(303)
    expect(continuation.headers.get('location')).toBe('/workspace?tab=recent')
  })

  it('keeps ordinary authenticated redirects and unauthenticated login forms', async () => {
    const ordinary = await fetch(`${running.baseUrl}/auth/login`, {
      redirect: 'manual', headers: { cookie: await signIn() },
    })
    expect(ordinary.status).toBe(303)
    const anonymous = await fetch(`${running.baseUrl}/auth/login`, { headers: navigation })
    expect(anonymous.status).toBe(200)
    const html = await anonymous.text()
    expect(html).toContain('name="password"')
    expect(html).not.toContain('http-equiv="refresh"')
  })

  it('keeps an unsafe return target on the authentication origin', async () => {
    const response = await navigate(`${running.baseUrl}/auth/login?returnTo=${encodeURIComponent('//attacker.invalid/')}`, await signIn())
    expect(response.status).toBe(200)
    expect(await response.text()).toContain('content="0;url=/auth/login?returnTo=%2F"')
  })
})
