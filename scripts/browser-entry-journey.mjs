/** Existing sessions must survive ordinary links from another browser origin. */
import http from 'node:http'
import { once } from 'node:events'

export async function proveAuthenticatedBrowserEntry(browser, httpsPort, waitForBrowser, authenticatedSpa) {
  const origin = `https://localhost:${String(httpsPort)}`
  let target = '/auth/login'
  const outside = http.createServer((_request, response) => {
    response.writeHead(200, { 'content-type': 'text/html; charset=utf-8', 'cache-control': 'no-store' })
    response.end(`<html><body><a id="entry" href="${origin}${target}">Open Harness</a></body></html>`)
  })
  outside.listen(0, '127.0.0.1')
  await once(outside, 'listening')
  const address = outside.address()
  if (address === null || typeof address === 'string') throw new Error('external navigation fixture did not bind')
  try {
    await waitForBrowser(browser.evaluate, authenticatedSpa, 'authenticated browser before external navigation')
    for (const destination of ['/auth/login', '/']) {
      target = destination
      await browser.navigate(`http://127.0.0.1:${String(address.port)}/`)
      await waitForBrowser(browser.evaluate, 'location.hostname === "127.0.0.1" && document.querySelector("#entry") !== null', 'external navigation fixture')
      await browser.evaluate('document.querySelector("#entry").click()')
      await waitForBrowser(browser.evaluate, authenticatedSpa, `existing session entering ${destination} from another origin`)
    }
  } finally {
    outside.close()
    await once(outside, 'close')
  }
}
