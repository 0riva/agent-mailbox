'use client';

/**
 * The consent screen for connecting an AI agent to the Oriva agent mailbox (o-core#2069).
 * Shows who is asking (the app's name AND the address it returns to, so a fake "Claude" is
 * visible), what the mailbox is for, and lets the owner choose the agent's role and the name their
 * other agents will see it by (an app may send a name that is not its own: Grok Bot sends "Cursor").
 */
import React, { useState } from 'react';
import { useRouter } from 'next/navigation';
import { Input, Text, XStack, YStack } from 'tamagui';

import { LOG_IN_RETURN_KEY } from '../../lib/signInReturn';

/** Remember this page (with its query), then open the log-in dialog; login returns here. */
function logInAndReturn(push: (href: string) => void): void {
  try {
    sessionStorage.setItem(LOG_IN_RETURN_KEY, window.location.pathname + window.location.search);
  } catch {
    /* lands on Pulse instead */
  }
  push('/login');
}

type Role = 'dispatcher' | 'worker';

type Props =
  | { state: 'invalid'; message: string }
  | { state: 'signed-out' | 'anonymous'; agentName: string }
  | {
      state: 'ready';
      agentName: string;
      returnHost: string;
      /** The return address proves who the app is (claude.ai). */
      verified: boolean;
      /** The app runs on this computer (a desktop app such as Grok Bot). */
      local: boolean;
      /** The signed-in account, masked. */
      account: string;
      request: { client_id: string; redirect_uri: string; code_challenge: string; state: string };
      /** Where the browser goes after Allow or Cancel; injectable because jsdom cannot replace location. */
      navigate?: (url: string) => void;
    };

const ROLES: Array<{ value: Role; title: string; body: string }> = [
  { value: 'dispatcher', title: 'Hands out work', body: 'Posts tasks for your other agents and reads their results.' },
  { value: 'worker', title: 'Does the work', body: 'Picks up tasks, reports results, and can leave notes.' },
];

function Shell({ children }: { children: React.ReactNode }) {
  return (
    <YStack flex={1} style={{ minHeight: '100vh' }} backgroundColor="$background" alignItems="center" justifyContent="center" padding="$4">
      <YStack width="100%" maxWidth={480} backgroundColor="$surface" borderColor="$borderColor" borderWidth={1} borderRadius={16} padding="$5" gap="$4">
        {children}
      </YStack>
    </YStack>
  );
}

function PrimaryButton({ label, onPress, disabled, testID }: { label: string; onPress: () => void; disabled?: boolean; testID: string }) {
  return (
    <Text
      tag="button"
      role="button"
      onPress={disabled ? undefined : onPress}
      aria-disabled={disabled}
      fontSize={16}
      fontWeight="700"
      color="$onButtonPrimary"
      backgroundColor="$buttonPrimary"
      hoverStyle={{ backgroundColor: '$buttonPrimaryHover' }}
      borderWidth={0}
      borderRadius={999}
      paddingHorizontal={22}
      paddingVertical={12}
      textAlign="center"
      cursor={disabled ? 'default' : 'pointer'}
      opacity={disabled ? 0.6 : 1}
      testID={testID}
    >
      {label}
    </Text>
  );
}

export function ConsentClient(props: Props) {
  const router = useRouter();
  const [role, setRole] = useState<Role | null>(null);
  const [name, setName] = useState(props.state === 'ready' ? props.agentName : '');
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);

  if (props.state === 'invalid') {
    return (
      <Shell>
        <Text fontSize={20} fontWeight="700" color="$textPrimary">This connection can’t go ahead</Text>
        <Text fontSize={16} color="$textSecondary" testID="consent-invalid">{props.message}</Text>
      </Shell>
    );
  }

  if (props.state !== 'ready') {
    return (
      <Shell>
        <Text fontSize={20} fontWeight="700" color="$textPrimary">Connect {props.agentName} to Oriva</Text>
        <Text fontSize={16} color="$textSecondary">
          {props.state === 'signed-out'
            ? 'Log in to your Oriva account to continue. You’ll come straight back here.'
            : 'Add an email to your Oriva account first, so your agents connect to an account you can get back into.'}
        </Text>
        {props.state === 'signed-out' && <PrimaryButton label="Log in" onPress={() => logInAndReturn(router.push)} testID="consent-log-in" />}
      </Shell>
    );
  }

  async function decide(decision: 'allow' | 'deny') {
    if (busy) return;
    if (decision === 'allow' && !role) {
      setError('Choose what this agent does.');
      return;
    }
    if (decision === 'allow' && !name.trim()) {
      setError('Give this agent a name.');
      return;
    }
    setBusy(true);
    setError(null);
    try {
      const res = await fetch('/api/mailbox/oauth/approve', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ ...(props as Extract<Props, { state: 'ready' }>).request, role, decision, name: name.trim() }),
      });
      const body = (await res.json().catch(() => ({}))) as { redirectTo?: string; error?: string };
      if (!res.ok || !body.redirectTo) throw new Error(body.error || 'Something went wrong. Try again.');
      const go = (props as Extract<Props, { state: 'ready' }>).navigate ?? ((url: string) => window.location.assign(url));
      go(body.redirectTo);
    } catch (e) {
      setError(e instanceof Error ? e.message : 'Something went wrong. Try again.');
      setBusy(false);
    }
  }

  return (
    <Shell>
      <YStack gap="$2">
        <Text fontSize={20} fontWeight="700" color="$textPrimary" testID="consent-title">
          Connect {props.agentName} to your agent mailbox
        </Text>
        <Text fontSize={15} color="$textSecondary" testID="consent-return-host">
          {props.local ? (
            <>It will return to an app on this computer (<Text fontWeight="700" color="$textPrimary">{props.returnHost}</Text>). Only continue if you just pressed Connect in that app.</>
          ) : (
            <>It will return to <Text fontWeight="700" color="$textPrimary">{props.returnHost}</Text>. Only continue if that is the app you are using.</>
          )}
        </Text>
        {!props.verified && !props.local ? (
          <Text fontSize={15} fontWeight="700" color="$textWarning" testID="consent-unverified">
            Unverified app: Oriva cannot confirm who made it. Anyone can give an app any name.
          </Text>
        ) : null}
        <Text fontSize={14} color="$textSecondary" testID="consent-account">
          Connecting to {props.account}.
        </Text>
      </YStack>

      <Text fontSize={15} color="$textSecondary">
        Your agents use the mailbox to pass work to each other. It carries messages, not memory: each one is sealed to the agent it is for and deleted after it is read. Your agents keep their own records on your system.
      </Text>

      <YStack gap="$2">
        <Text fontSize={16} fontWeight="700" color="$textPrimary">Name</Text>
        <Input
          value={name}
          onChangeText={(v: string) => {
            setName(v);
            setError(null);
          }}
          maxLength={100}
          aria-label="Agent name"
          fontSize={16}
          color="$textPrimary"
          backgroundColor="$surface"
          borderColor="$borderColor"
          testID="consent-name"
        />
        <Text fontSize={14} color="$textSecondary">
          Your other agents will find it by this name. Change it if the app sent the wrong one: Grok Bot, for example, arrives as Cursor.
        </Text>
      </YStack>

      <YStack gap="$2" role="radiogroup" aria-label="What this agent does">
        {ROLES.map((r) => {
          const chosen = role === r.value;
          return (
            <YStack
              key={r.value}
              tag="button"
              role="radio"
              aria-checked={chosen}
              onPress={() => {
                setRole(r.value);
                setError(null);
              }}
              backgroundColor={chosen ? '$selectedFill' : '$surface'}
              hoverStyle={{ backgroundColor: chosen ? '$selectedFillHover' : '$backgroundHover' }}
              borderColor={chosen ? '$colorAccent' : '$borderColor'}
              borderWidth={1}
              borderRadius={12}
              padding="$3"
              gap="$1"
              cursor="pointer"
              testID={`consent-role-${r.value}`}
            >
              <Text fontSize={16} fontWeight="700" color={chosen ? '$onSelectedFill' : '$textPrimary'}>{r.title}</Text>
              <Text fontSize={15} color="$textSecondary">{r.body}</Text>
            </YStack>
          );
        })}
      </YStack>

      <Text fontSize={14} color="$textSecondary">
        Messages are encrypted with keys Oriva does not keep, so Oriva staff cannot read them from the database. The AI providers you use do read them, as they must to act on them. If you share this agent into a project with another company, that company’s AI provider also reads what this agent sends to their agents. You can stop this agent at any time in Settings → Agents.
      </Text>

      {error && <Text fontSize={15} color="$textDanger" role="alert" testID="consent-error">{error}</Text>}

      <XStack gap="$3" justifyContent="flex-end" flexWrap="wrap">
        <Text
          tag="button"
          role="button"
          onPress={() => decide('deny')}
          fontSize={16}
          fontWeight="600"
          color="$textPrimary"
          backgroundColor="transparent"
          borderWidth={1}
          borderColor="$borderColor"
          borderRadius={999}
          paddingHorizontal={22}
          paddingVertical={12}
          cursor="pointer"
          testID="consent-cancel"
        >
          Cancel
        </Text>
        <PrimaryButton label={busy ? 'Connecting…' : 'Allow'} onPress={() => decide('allow')} disabled={busy} testID="consent-allow" />
      </XStack>
    </Shell>
  );
}
