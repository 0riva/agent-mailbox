/**
 * The mailbox's playbook, served through the MCP Skills extension (o-core#2367). An assistant that
 * supports skills lists it by name and description and reads it only when it is about to hand out
 * or do work through the mailbox.
 *
 * Kept in code so the serverless route reads no files. The manifest digest is computed from the exact
 * bytes served, as the extension requires (`skills/list` → `resources[].digest`).
 */
import { createHash } from 'node:crypto';

export const SKILL_NAME = 'oriva-mailbox';
export const SKILL_URI = `skill://${SKILL_NAME}/SKILL.md`;

export const SKILL_MD = `---
name: ${SKILL_NAME}
description: Hand work to another AI agent, or do work handed to you, through the Oriva agent mailbox — who to give a task to, how its result comes back, and what to do when nothing has arrived. Use before calling post_task, read_replies, next_task, report or note.
---

# Working through the Oriva agent mailbox

The mailbox connects AI agents on one Oriva account (and, inside a shared project, agents of other
companies). Each agent either **hands out work** or **does the work**; the tools you see depend on which.

## If you hand out work

1. \`list_agents\` shows who can take a task and what each one does.
2. \`post_task\` with \`text\`: the whole task, self-contained. The other agent sees nothing else
   of this conversation. Name the agent in \`to\` when more than one could take it. Another company's
   agent is named by its id, or by its name with \`project\`.
3. Getting the result:
   - If your assistant follows background tasks, \`post_task\` returns a task and the result arrives
     by itself when the agent reports. You can carry on with other work meanwhile.
   - Otherwise call \`read_replies\` later. Each result and note is shown once, so keep what you need.
4. Agents usually work on a schedule, so a result can take minutes or hours. Waiting is normal.
5. Changed your mind? Cancelling the background task withdraws it: an agent that has not picked it up
   never sees it, and one that has is told its result is no longer wanted.

## If you do the work

1. \`next_task\` fetches the oldest task waiting for you. Call it when asked to check in, and at the
   start of every scheduled run.
2. Do the task, then \`report\` with the \`task_id\` you were given and the full answer in \`result\`.
3. \`note\` sends anything that is not a result: a question, a progress update, something you noticed.
4. If \`report\` says the task was withdrawn, stop: the agent that gave it no longer wants the result.

## Limits

- One message is at most 200 KB. Send a summary, or split it.
- An agent holds at most 20 MB of unread messages. When it is full, wait until it catches up.
- Messages are deleted 7 days after they are read. The mailbox is for passing work, not for keeping it.
`;

const bytes = Buffer.from(SKILL_MD, 'utf8');

export const SKILL_ENTRY = {
  uri: SKILL_URI,
  frontmatter: {
    name: SKILL_NAME,
    description: /\ndescription: (.+)\n/.exec(SKILL_MD)?.[1] ?? '',
  },
  resources: [{ uri: SKILL_URI, digest: `sha256:${createHash('sha256').update(bytes).digest('hex')}`, size: bytes.length }],
};
