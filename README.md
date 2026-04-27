# Snickr

A web-based team messaging system with a relational database design in Postgresql, built as part of our NYU graduate level database systems course. Snickr is modeled after Slack — users can create workspaces, invite members, create channels, and exchange messages.

## Features

- **Workspaces** — users can create and manage workspaces with multiple administrators
- **Channels** — three channel types: public (open to all workspace members), private (invite-only), and direct (two-person)
- **Messages** — chronological message history per channel with read-receipt tracking
- **Invitations** — full invitation lifecycle (pending → accepted / declined) for both workspaces and channels

## Repository Contents

| File | Description |
|---|---|
| `schema.sql` | PostgreSQL table definitions, constraints, and indexes |
| `sample_data.sql` | Sample data for two workspaces (CS Department + Startup HQ) with realistic test cases |
| `queries.sql` | Sample queries covering common operations: posting messages, searching by keyword, listing admins, and access-controlled message retrieval |

## Schema Overview

| Table | Type | Description |
|---|---|---|
| `users` | Strong entity | Accounts with email, username, nickname, and hashed password |
| `workspaces` | Strong entity | Named workspaces with a designated creator/admin |
| `workspace_membership` | Weak entity | Tracks which users belong to which workspace and their admin status |
| `workspace_invitation` | Strong entity | Invitation records including pending invites to non-users (by email) |
| `channels` | Strong entity | Public, private, or direct channels within a workspace |
| `channel_membership` | Weak entity | Tracks which users belong to which channel |
| `channel_invitation` | Strong entity | Invitation records for private and direct channels |
| `messages` | Strong entity | Messages posted in a channel, ordered chronologically |
| `is_seen` | Weak entity | Per-user read receipts for each message |

## Setup

Requires PostgreSQL with the `pgcrypto` extension for password hashing.

```sql
CREATE EXTENSION IF NOT EXISTS pgcrypto;
\i schema.sql
\i sample_data.sql
```

## Course

Database Systems — Final Project
