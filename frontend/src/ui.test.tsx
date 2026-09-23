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
