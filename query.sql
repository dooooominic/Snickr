/* Queries for Project Part 1 */

--1 
INSERT INTO users (user_email, username, nickname, password_hash)
VALUES (
    'testuser@gmail.com',
    'ilovedatabases',
    'TestUser1',
    'password12345'
);

--2
WITH auth_check AS (
    SELECT 1
    FROM workspace_membership
    WHERE workspace_id = 'bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb' --uuid format
      AND user_id = 'aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa'
)
INSERT INTO channels (workspace_id, channel_name, channel_type, creator_id)
SELECT
    'bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb',
    'first channel',
    'public',
    'aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa'
WHERE EXISTS (SELECT 1 FROM auth_check);

-- have teo also add the creator as a member of their new channel!
INSERT INTO channel_membership (channel_id, user_id)
SELECT c.channel_id, c.creator_id
FROM channels c
WHERE c.creator_id = 'aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa'
  AND c.workspace_id = 'bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb'
  AND c.channel_name = 'general';

--3
SELECT
    w.workspace_id,
    w.workspace_name,
    u.user_id,
    u.username,
FROM workspaces w
JOIN workspace_membership wm ON w.workspace_id = wm.workspace_id
JOIN users u ON wm.user_id = u.user_id
WHERE wm.is_admin = true
ORDER BY w.workspace_name, u.username;

--4
SELECT
    c.channel_id,
    c.channel_name,
    COUNT(ci.invitee_user_id) AS invited_but_not_joined
FROM channels c
LEFT JOIN channel_invitation ci
ON c.channel_id = ci.channel_id
    AND ci.invite_status   = 'pending'
    AND ci.invitation_time < now() - INTERVAL '5 days'
    AND NOT EXISTS ( --users still not in channel
        SELECT 1
        FROM channel_membership cm
        WHERE cm.channel_id = ci.channel_id AND cm.user_id = ci.invitee_user_id
          )
WHERE c.workspace_id = 'bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb'
  AND c.channel_type = 'public'
GROUP BY c.channel_id, c.channel_name
ORDER BY c.channel_name;

--5
SELECT
    m.message_id,
    m.message_time,
    u.username, --need users too. can't just return messages
    u.nickname,
    m.message_text
FROM messages m
JOIN users u ON m.user_id = u.user_id
WHERE m.channel_id = 'cccccccc-cccc-cccc-cccc-cccccccccccc'
ORDER BY m.message_time ASC;

--6
SELECT
    m.message_id,
    m.message_time,
    c.channel_name,
    c.channel_type,
    w.workspace_name,
    m.message_text
FROM messages m
JOIN channels c ON m.channel_id = c.channel_id
JOIN workspaces w ON c.workspace_id = w.workspace_id
WHERE m.user_id = 'aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa'
ORDER BY m.message_time ASC;

--7
SELECT
    m.message_id,
    m.message_time,
    u_author.username AS posted_by,
    w.workspace_name,
    c.channel_name,
    m.message_text
FROM messages m
JOIN channels c ON m.channel_id = c.channel_id
JOIN workspaces w ON c.workspace_id = w.workspace_id
JOIN users u_author ON m.user_id = u_author.user_id
-- user must be a member of the channel
JOIN channel_membership cm ON cm.channel_id = c.channel_id
AND cm.user_id = 'aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa'
-- user must be a member of the workspace
JOIN workspace_membership wm ON wm.workspace_id = w.workspace_id
AND wm.user_id = 'aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa'
-- full-text keyword search
WHERE m.message_text ILIKE '%perpendicular%'
ORDER BY m.message_time ASC;