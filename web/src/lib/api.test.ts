/**
 * API client tests: request shape, error mapping, response types.
 * The network is stubbed: no real call leaves here.
 */

import { afterEach, describe, expect, it, vi } from 'vitest'

import { api, ApiError } from './api'

function jsonResponse(body: unknown, status = 200): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: { 'content-type': 'application/json' },
  })
}

function stubFetch(response: Response): ReturnType<typeof vi.fn> {
  const mock = vi.fn().mockResolvedValue(response)
  vi.stubGlobal('fetch', mock)
  return mock
}

afterEach(() => {
  vi.unstubAllGlobals()
})

describe('api.login', () => {
  it('posts the credentials and returns the session', async () => {
    const mock = stubFetch(jsonResponse({ name: 'j.doe', roles: ['analyst'] }))

    const session = await api.login('j.doe', 'a passphrase')

    expect(mock).toHaveBeenCalledOnce()
    const [url, init] = mock.mock.calls[0]
    expect(url).toBe('/api/auth/login')
    expect(init.method).toBe('POST')
    expect(JSON.parse(init.body)).toEqual({ username: 'j.doe', password: 'a passphrase' })
    expect(session).toEqual({ name: 'j.doe', roles: ['analyst'] })
  })
})

describe('error handling', () => {
  it('maps the structured detail to ApiError', async () => {
    stubFetch(
      jsonResponse(
        {
          detail: {
            error: 'egress_blocked',
            message: 'Search refused.',
            hint: 'Continue with the provided IOCs.',
          },
        },
        400,
      ),
    )

    const failure = await api.listIocs('hunt_x').catch((error: unknown) => error)

    expect(failure).toBeInstanceOf(ApiError)
    const apiError = failure as ApiError
    expect(apiError.status).toBe(400)
    expect(apiError.code).toBe('egress_blocked')
    expect(apiError.message).toBe('Search refused.')
    expect(apiError.hint).toBe('Continue with the provided IOCs.')
  })

  it('keeps a default message on an unreadable body', async () => {
    stubFetch(new Response('outage', { status: 500 }))

    const failure = await api.dashboard().catch((error: unknown) => error)

    expect(failure).toBeInstanceOf(ApiError)
    expect((failure as ApiError).message).toContain('500')
  })
})

describe('response formats', () => {
  it('a 204 response returns undefined', async () => {
    stubFetch(new Response(null, { status: 204 }))
    await expect(api.logout()).resolves.toBeUndefined()
  })

  it('a text response is returned as-is', async () => {
    stubFetch(
      new Response('# Report', {
        status: 200,
        headers: { 'content-type': 'text/markdown' },
      }),
    )
    await expect(api.reportMarkdown('hunt_x')).resolves.toBe('# Report')
  })

  it('the PDF export rejects an error cleanly', async () => {
    stubFetch(jsonResponse({ detail: 'Report unavailable.' }, 404))

    const failure = await api.reportPdf('hunt_x').catch((error: unknown) => error)

    expect(failure).toBeInstanceOf(ApiError)
    expect((failure as ApiError).status).toBe(404)
    expect((failure as ApiError).message).toBe('Report unavailable.')
  })
})

describe('write-only secrets', () => {
  it('writing a key goes out as a PUT and returns nothing', async () => {
    const mock = stubFetch(new Response(null, { status: 204 }))

    await api.setSecret('OTX_API_KEY', 'value')

    const [url, init] = mock.mock.calls[0]
    expect(url).toBe('/api/config/secrets/OTX_API_KEY')
    expect(init.method).toBe('PUT')
  })
})
