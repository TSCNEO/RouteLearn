// @vitest-environment jsdom
import { fireEvent, render, screen, waitFor } from '@testing-library/react'
import { afterEach, expect, test, vi } from 'vitest'
import { App, Auth } from './ui'

afterEach(() => vi.unstubAllGlobals())

test('first-run admin setup sends code and signs in', async () => {
  const fetchMock = vi.fn().mockResolvedValue({ ok: true, json: async () => ({ status: 'created' }) })
  vi.stubGlobal('fetch', fetchMock)
  const done = vi.fn()
  render(<Auth needsSetup onDone={done} />)
  fireEvent.change(screen.getByLabelText('Username'), { target: { value: 'admin' } })
  fireEvent.change(screen.getByLabelText('Password'), { target: { value: 'a-long-password-123' } })
  fireEvent.change(screen.getByLabelText('Setup code'), { target: { value: 'one-time-code' } })
  fireEvent.click(screen.getByRole('button', { name: /Create account/ }))
  await waitFor(() => expect(done).toHaveBeenCalledOnce())
  expect(fetchMock).toHaveBeenCalledTimes(2)
  expect(fetchMock.mock.calls[0][0]).toBe('/api/v1/auth/setup')
  expect(JSON.parse(fetchMock.mock.calls[0][1].body)).toEqual({ username: 'admin', password: 'a-long-password-123', setup_code: 'one-time-code' })
  expect(fetchMock.mock.calls[1][0]).toBe('/api/v1/auth/login')
})

test('agent token remains visible after the post-create data refresh', async () => {
  vi.stubGlobal('EventSource', class { close() {} })
  const fetchMock = vi.fn(async (input: string, init?: RequestInit) => {
    const path = String(input)
    const data = path.endsWith('/auth/status') ? { needs_setup: false }
      : path.endsWith('/auth/me') ? { username: 'admin' }
      : path.endsWith('/agents') && init?.method === 'POST' ? { token: 'one-time-agent-token' }
      : path.endsWith('/agents') ? []
      : {}
    return { ok: true, json: async () => data }
  })
  vi.stubGlobal('fetch', fetchMock)
  render(<App />)
  fireEvent.click(await screen.findByRole('button', { name: 'DNS agents' }))
  fireEvent.change(screen.getByLabelText('Agent name'), { target: { value: 'test-dns' } })
  fireEvent.click(screen.getByRole('button', { name: /Create agent/ }))
  await waitFor(() => expect(screen.getByText('one-time-agent-token')).toBeTruthy())
  expect(fetchMock).toHaveBeenCalledWith('/api/v1/agents', expect.objectContaining({ method: 'POST' }))
})

test('learning mode creates an editable service without a router', async () => {
  vi.stubGlobal('EventSource', class { close() {} })
  const services: { id: number; name: string; patterns: string[]; live_window_hours: number; warmup_window_hours: number; retention_days: number }[] = []
  const fetchMock = vi.fn(async (input: string, init?: RequestInit) => {
    const path = String(input)
    let data: unknown = {}
    if (path.endsWith('/auth/status')) data = { needs_setup: false }
    else if (path.endsWith('/auth/me')) data = { username: 'admin' }
    else if (path.endsWith('/services') && init?.method === 'POST') {
      const body = JSON.parse(String(init.body))
      services.push({ id: 1, name: body.name, patterns: body.patterns, live_window_hours: 168, warmup_window_hours: 72, retention_days: 90 })
      data = services[0]
    } else if (path.endsWith('/services')) data = [...services]
    else if (path.endsWith('/services/1/ips')) data = []
    return { ok: true, json: async () => data }
  })
  vi.stubGlobal('fetch', fetchMock)
  render(<App />)
  fireEvent.click(await screen.findByRole('button', { name: 'Services' }))
  fireEvent.click(screen.getByRole('button', { name: /Use YouTube template/ }))
  expect((screen.getByLabelText('Service name') as HTMLInputElement).value).toBe('YouTube')
  fireEvent.click(screen.getByRole('button', { name: /Create service/ }))
  const count = await screen.findByText('7 domain patterns')
  fireEvent.click(count.closest('button')!)
  expect(screen.getByRole('button', { name: 'Save service settings' })).toBeTruthy()
  expect(services[0].name).toBe('YouTube')
  expect(services[0].patterns).toContain('*.googlevideo.com')
})
