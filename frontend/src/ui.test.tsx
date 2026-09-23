// @vitest-environment jsdom
import { fireEvent, render, screen, waitFor } from '@testing-library/react'
import { afterEach, expect, test, vi } from 'vitest'
import { Auth } from './ui'

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
