/**
 * The consent screen (o-core#2069): the owner must choose a role before Allow does anything; Allow
 * and Cancel post to the approve endpoint and follow its answer; errors are shown, not swallowed;
 * a signed-out owner's Log in remembers this page so login returns here.
 */
export {};

import React from 'react';
import { act, fireEvent, render } from '@testing-library/react-native';

const mockPush = jest.fn();
jest.mock('next/navigation', () => ({ useRouter: () => ({ push: mockPush }) }));
jest.mock('tamagui', () => {
  const R = jest.requireActual('react');
  // Host elements by name: queryable by testID and pressable, without loading react-native's natives.
  const box = ({ children, onPress, testID }: { children?: React.ReactNode; onPress?: () => void; testID?: string }) =>
    R.createElement('View', { onPress, testID }, children);
  const text = ({ children, onPress, testID }: { children?: React.ReactNode; onPress?: () => void; testID?: string }) =>
    R.createElement('Text', { onPress, testID }, children);
  const input = ({ value, onChangeText, testID }: { value?: string; onChangeText?: (v: string) => void; testID?: string }) =>
    R.createElement('TextInput', { value, onChangeText, testID });
  return { YStack: box, XStack: box, Text: text, Input: input };
});

const { ConsentClient } = require('../ConsentClient') as typeof import('../ConsentClient');

const request = { client_id: 'mbc_1', redirect_uri: 'https://claude.ai/cb', code_challenge: 'c'.repeat(43), state: 's' };
let assign: jest.Mock;
const readyEl = (extra: { verified?: boolean; local?: boolean; returnHost?: string } = {}) => (
  <ConsentClient state="ready" agentName="Claude" returnHost={extra.returnHost ?? 'claude.ai'} verified={extra.verified ?? true} local={extra.local ?? false} account="g***@example.com" request={request} navigate={assign} />
);

let fetchMock: jest.Mock;
beforeEach(() => {
  fetchMock = jest.fn();
  (global as unknown as { fetch: jest.Mock }).fetch = fetchMock;
  assign = jest.fn();
  mockPush.mockReset();
  sessionStorage.clear();
});
afterEach(() => jest.restoreAllMocks());

const flush = () => act(async () => { await new Promise((r) => setTimeout(r, 0)); });

it('names the app and the address it returns to', () => {
  const { getByTestId, toJSON } = render(readyEl());
  expect(getByTestId('consent-title').props.children.join('')).toContain('Claude');
  const tree = JSON.stringify(toJSON());
  expect(tree).toContain('It will return to');
  expect(tree).toContain('claude.ai');
});

it('warns that an app it cannot verify may not be who it says, and names the account', () => {
  const { queryByTestId, toJSON } = render(readyEl({ verified: false, returnHost: 'claude-ai.example' }));
  expect(queryByTestId('consent-unverified')).not.toBeNull();
  expect(JSON.stringify(toJSON())).toContain('g***@example.com');
  expect(render(readyEl()).queryByTestId('consent-unverified')).toBeNull();
});

it('describes a desktop app as one on this computer, without the unverified warning', () => {
  const { queryByTestId, toJSON } = render(readyEl({ verified: false, local: true, returnHost: '127.0.0.1:18787' }));
  expect(JSON.stringify(toJSON())).toContain('an app on this computer');
  expect(queryByTestId('consent-unverified')).toBeNull();
});

it('will not Allow until a role is chosen', async () => {
  const { getByTestId } = render(readyEl());
  fireEvent.press(getByTestId('consent-allow'));
  await flush();
  expect(fetchMock).not.toHaveBeenCalled();
  expect(getByTestId('consent-error').props.children).toBe('Choose what this agent does.');
});

it('choosing a role clears the "choose a role" message', async () => {
  const { getByTestId, queryByTestId } = render(readyEl());
  fireEvent.press(getByTestId('consent-allow'));
  await flush();
  expect(queryByTestId('consent-error')).not.toBeNull();
  fireEvent.press(getByTestId('consent-role-dispatcher'));
  expect(queryByTestId('consent-error')).toBeNull();
});

it('Allow posts the request with the chosen role and follows the answer', async () => {
  fetchMock.mockResolvedValue({ ok: true, json: async () => ({ redirectTo: 'https://claude.ai/cb?code=omb_x' }) });
  const { getByTestId } = render(readyEl());
  fireEvent.press(getByTestId('consent-role-worker'));
  fireEvent.press(getByTestId('consent-allow'));
  await flush();
  const [url, init] = fetchMock.mock.calls[0];
  expect(url).toBe('/api/mailbox/oauth/approve');
  expect(JSON.parse(init.body)).toEqual({ ...request, role: 'worker', decision: 'allow', name: 'Claude' });
  expect(assign).toHaveBeenCalledWith('https://claude.ai/cb?code=omb_x');
});

it('starts the name box at the name the app sent, and posts the name the owner typed', async () => {
  fetchMock.mockResolvedValue({ ok: true, json: async () => ({ redirectTo: 'https://claude.ai/cb?code=omb_x' }) });
  const { getByTestId } = render(readyEl());
  expect(getByTestId('consent-name').props.value).toBe('Claude');
  fireEvent.changeText(getByTestId('consent-name'), '  Grok Bot ');
  fireEvent.press(getByTestId('consent-role-worker'));
  fireEvent.press(getByTestId('consent-allow'));
  await flush();
  expect(JSON.parse(fetchMock.mock.calls[0][1].body).name).toBe('Grok Bot');
});

it('will not Allow with an empty name', async () => {
  const { getByTestId } = render(readyEl());
  fireEvent.changeText(getByTestId('consent-name'), '   ');
  fireEvent.press(getByTestId('consent-role-worker'));
  fireEvent.press(getByTestId('consent-allow'));
  await flush();
  expect(fetchMock).not.toHaveBeenCalled();
  expect(getByTestId('consent-error').props.children).toBe('Give this agent a name.');
});

it('Cancel posts a denial without needing a role', async () => {
  fetchMock.mockResolvedValue({ ok: true, json: async () => ({ redirectTo: 'https://claude.ai/cb?error=access_denied' }) });
  const { getByTestId } = render(readyEl());
  fireEvent.press(getByTestId('consent-cancel'));
  await flush();
  expect(JSON.parse(fetchMock.mock.calls[0][1].body).decision).toBe('deny');
  expect(assign).toHaveBeenCalled();
});

it('shows the server\'s error and does not navigate', async () => {
  fetchMock.mockResolvedValue({ ok: false, json: async () => ({ error: 'Sign in first.' }) });
  const { getByTestId } = render(readyEl());
  fireEvent.press(getByTestId('consent-role-dispatcher'));
  fireEvent.press(getByTestId('consent-allow'));
  await flush();
  expect(getByTestId('consent-error').props.children).toBe('Sign in first.');
  expect(assign).not.toHaveBeenCalled();
});

it('signed out: Log in remembers this page, then opens the log-in dialog', () => {
  const { getByTestId } = render(<ConsentClient state="signed-out" agentName="Grok Bot" />);
  fireEvent.press(getByTestId('consent-log-in'));
  expect(sessionStorage.getItem('oriva_otp_redirect')).toBe(window.location.pathname + window.location.search);
  expect(mockPush).toHaveBeenCalledWith('/login');
});

it('an invalid request shows its message and no buttons', () => {
  const { getByTestId, queryByTestId } = render(<ConsentClient state="invalid" message="This app is not registered with Oriva." />);
  expect(getByTestId('consent-invalid').props.children).toBe('This app is not registered with Oriva.');
  expect(queryByTestId('consent-allow')).toBeNull();
});
