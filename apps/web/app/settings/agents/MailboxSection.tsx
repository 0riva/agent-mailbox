'use client';

/**
 * Settings → Agents → Agent mailbox (o-core#2069): the AI agents connected to this account's
 * mailbox (Claude, Grok Bot, …), what each does, a Stop button for each, and the recent activity.
 * Contents are never shown: the mailbox carries messages between agents, not memory, and the
 * agents keep their own records.
 */
import { useCallback, useEffect, useState } from 'react';
import { YStack, XStack, Text, Button, Input, Separator, Spinner } from 'tamagui';
import { Card } from '@oriva/ui/atoms/Card.bento';

export interface MailboxAgent {
  id: string;
  name: string;
  role: 'dispatcher' | 'worker';
  connectedAt: string;
  lastUsedAt: string | null;
  stoppedAt: string | null;
}

export interface MailboxActivity {
  id: string;
  from: string;
  to: string;
  kind: 'task' | 'result' | 'note';
  size: number;
  sentAt: string;
  readAt: string | null;
}

const ROLE_LABEL = { dispatcher: 'Hands out work', worker: 'Does the work' } as const;
const KIND_LABEL = { task: 'Task', result: 'Result', note: 'Note' } as const;

export function MailboxSection() {
  const [data, setData] = useState<{ agents: MailboxAgent[]; activity: MailboxActivity[] } | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [stopping, setStopping] = useState<string | null>(null);
  const [renaming, setRenaming] = useState<{ id: string; name: string } | null>(null);

  const load = useCallback(async () => {
    try {
      const res = await fetch('/api/agents/mailbox', { cache: 'no-store' });
      const body = await res.json().catch(() => ({}));
      if (!res.ok) throw new Error(body.error || 'Could not read your agent mailbox.');
      setData(body);
      setError(null);
    } catch (e) {
      setError(e instanceof Error ? e.message : 'Could not read your agent mailbox.');
    }
  }, []);

  useEffect(() => {
    void load();
  }, [load]);

  const stop = async (agent: MailboxAgent) => {
    setStopping(agent.id);
    try {
      const res = await fetch('/api/agents/mailbox', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ connectionId: agent.id }),
      });
      const body = await res.json().catch(() => ({}));
      if (!res.ok) throw new Error(body.error || 'Could not stop that agent.');
      await load();
    } catch (e) {
      setError(e instanceof Error ? e.message : 'Could not stop that agent.');
    } finally {
      setStopping(null);
    }
  };

  const saveName = async () => {
    if (!renaming) return;
    try {
      const res = await fetch('/api/agents/mailbox', {
        method: 'PATCH',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ connectionId: renaming.id, name: renaming.name }),
      });
      const body = await res.json().catch(() => ({}));
      if (!res.ok) throw new Error(body.error || 'Could not rename that agent.');
      setRenaming(null);
      await load();
    } catch (e) {
      setError(e instanceof Error ? e.message : 'Could not rename that agent.');
    }
  };

  const connected = data?.agents.filter((a) => !a.stoppedAt) ?? [];

  return (
    <YStack gap="$2" testID="mailbox-section">
      <Text fontSize="$5" fontWeight="700" color="$color">Agent mailbox</Text>
      <Text fontSize="$3" color="$colorPress">
        AI agents you connected from Claude, Grok Bot or another app pass work to each other here. Each message is sealed to the agent it is
        for and deleted a week after it is read, so the contents are never shown here — your agents keep their own records. An agent you
        share into a project with another company can also pass work to that company’s agents; that company’s AI provider reads what is sent to them.
      </Text>
      {error ? <Text fontSize="$3" color="$textDanger" role="alert" testID="mailbox-error">{error}</Text> : null}
      {!data && !error ? <Spinner /> : null}
      {data ? (
        <>
          <Card padding="none">
            {connected.length ? (
              <YStack testID="mailbox-agents">
                {connected.map((a, i) => (
                  <YStack key={a.id}>
                    {i > 0 ? <Separator /> : null}
                    <XStack padding="$4" gap="$3" alignItems="center" justifyContent="space-between" flexWrap="wrap">
                      <YStack gap="$1" flex={1} minWidth={200}>
                        {renaming?.id === a.id ? (
                          <XStack gap="$2" alignItems="center">
                            <Input
                              flex={1}
                              value={renaming.name}
                              onChangeText={(name: string) => setRenaming({ id: a.id, name })}
                              maxLength={100}
                              aria-label={`New name for ${a.name}`}
                              color="$color"
                              testID={`mailbox-name-${a.id}`}
                            />
                            <Button size="$3" onPress={() => void saveName()} testID={`mailbox-save-${a.id}`}>Save</Button>
                            <Button size="$3" chromeless onPress={() => setRenaming(null)} testID={`mailbox-cancel-${a.id}`}>Cancel</Button>
                          </XStack>
                        ) : (
                          <Text color="$color" fontWeight="700">{a.name}</Text>
                        )}
                        <Text color="$colorPress" fontSize="$3">
                          {ROLE_LABEL[a.role]} · connected {new Date(a.connectedAt).toLocaleDateString()}
                          {a.lastUsedAt ? ` · last active ${new Date(a.lastUsedAt).toLocaleString()}` : ''}
                        </Text>
                      </YStack>
                      <XStack gap="$2">
                        {renaming?.id === a.id ? null : (
                          <Button size="$3" chromeless onPress={() => setRenaming({ id: a.id, name: a.name })} testID={`mailbox-rename-${a.id}`}>
                            Rename
                          </Button>
                        )}
                        <Button size="$3" onPress={() => void stop(a)} disabled={stopping === a.id} testID={`mailbox-stop-${a.id}`}>
                          {stopping === a.id ? 'Stopping…' : 'Stop'}
                        </Button>
                      </XStack>
                    </XStack>
                  </YStack>
                ))}
              </YStack>
            ) : (
              <Text padding="$4" color="$colorPress" fontSize="$3" testID="mailbox-empty">
                No agents connected. Add Oriva as a connector in Claude or Grok Bot, and choose what each agent does when it asks.
              </Text>
            )}
          </Card>
          {data.activity.length ? (
            <Card padding="none">
              <YStack testID="mailbox-activity">
                {data.activity.map((m, i) => (
                  <YStack key={m.id}>
                    {i > 0 ? <Separator /> : null}
                    <YStack padding="$4" gap="$1">
                      <Text color="$color">{KIND_LABEL[m.kind]} from {m.from} to {m.to}</Text>
                      <Text color="$colorPress" fontSize="$3">
                        {new Date(m.sentAt).toLocaleString()} · {m.readAt ? `read ${new Date(m.readAt).toLocaleString()}` : 'not read yet'}
                      </Text>
                    </YStack>
                  </YStack>
                ))}
              </YStack>
            </Card>
          ) : null}
        </>
      ) : null}
    </YStack>
  );
}
