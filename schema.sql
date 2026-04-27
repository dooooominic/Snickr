

/* 

User: 
  creates workspace 
  creates channel 

Workspace: 
    contains channel 1:N

Channel: 

Message: 
    user sends messages 
    in channel/workspace 

Invitation:
    userid/inviter 
    general invitation, no second userid needed



*/

CREATE TABLE Users (
    user_id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_email TEXT NOT NULL UNIQUE,
    username TEXT NOT NULL UNIQUE,
    nickname TEXT,
    password_hash TEXT NOT NULL,
    user_creation_time TIMESTAMP NOT NULL DEFAULT now()
);

CREATE TABLE Workspaces (
    workspace_id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    workspace_name TEXT NOT NULL,
    workspace_creation_time TIMESTAMP NOT NULL DEFAULT now(),
    creator_id UUID NOT NULL REFERENCES users(user_id)
);

CREATE TABLE Workspace_Membership (
    workspace_id UUID NOT NULL REFERENCES workspaces(workspace_id) ON DELETE CASCADE,
    user_id UUID NOT NULL REFERENCES users(user_id) ON DELETE CASCADE,
    is_admin BOOLEAN NOT NULL DEFAULT false,
    joined_time TIMESTAMP NOT NULL DEFAULT now(),
    PRIMARY KEY (workspace_id, user_id)
);

CREATE TABLE Workspace_Invitation (
    invitation_id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    inviter_user_id UUID NOT NULL REFERENCES users(user_id),
    invitee_email TEXT NOT NULL,
    invitee_user_id UUID REFERENCES users(user_id),
    workspace_id UUID NOT NULL REFERENCES workspaces(workspace_id) ON DELETE CASCADE,
    invite_status TEXT NOT NULL DEFAULT 'pending'
        CHECK (invite_status IN ('pending', 'accepted', 'declined')),

    invitation_time TIMESTAMP NOT NULL DEFAULT now(),
    responded_at TIMESTAMP,

    CONSTRAINT chk_responded CHECK (
        (invite_status = 'pending' AND responded_at IS NULL) OR
        (invite_status <> 'pending' AND responded_at IS NOT NULL)
    )
);

CREATE TABLE Channels (
    channel_id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    workspace_id UUID NOT NULL REFERENCES workspaces(workspace_id) ON DELETE CASCADE,
    channel_name TEXT NOT NULL,
    channel_type TEXT NOT NULL CHECK (channel_type IN ('public', 'private', 'direct')),
    creator_id UUID NOT NULL REFERENCES users(user_id),
    created_at TIMESTAMP NOT NULL DEFAULT now()
);

CREATE TABLE Channel_Membership (
    channel_id UUID NOT NULL REFERENCES channels(channel_id) ON DELETE CASCADE,
    user_id UUID NOT NULL REFERENCES users(user_id) ON DELETE CASCADE,
    joined_time TIMESTAMP NOT NULL DEFAULT now(),
    PRIMARY KEY (channel_id, user_id)
);

CREATE TABLE Channel_Invitation (
    invitation_id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    inviter_user_id UUID NOT NULL REFERENCES users(user_id),
    invitee_user_id UUID NOT NULL REFERENCES users(user_id),
    channel_id UUID NOT NULL REFERENCES channels(channel_id) ON DELETE CASCADE,
    invite_status TEXT NOT NULL DEFAULT 'pending'
                        CHECK (invite_status IN ('pending', 'accepted', 'declined')),

    invitation_time TIMESTAMP NOT NULL DEFAULT now(),
    responded_at TIMESTAMP,

    CONSTRAINT chk_not_self_invite CHECK (inviter_user_id <> invitee_user_id),
    CONSTRAINT chk_responded CHECK (
        (invite_status = 'pending' AND responded_at IS NULL) OR
        (invite_status <> 'pending' AND responded_at IS NOT NULL)
    )
);

CREATE TABLE Messages (
    message_id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    channel_id UUID NOT NULL REFERENCES channels(channel_id) ON DELETE CASCADE,
    user_id UUID NOT NULL REFERENCES users(user_id),
    message_text TEXT NOT NULL,
    message_time TIMESTAMP NOT NULL DEFAULT now()
);

CREATE TABLE Is_Seen (
    message_id UUID NOT NULL REFERENCES messages(message_id) ON DELETE CASCADE,
    user_id UUID NOT NULL REFERENCES users(user_id) ON DELETE CASCADE,
    is_seen BOOLEAN NOT NULL DEFAULT false,
    seen_time TIMESTAMP,
    PRIMARY KEY (message_id, user_id),
    
    CONSTRAINT chk_seen_time CHECK (
        (is_seen = false AND seen_time IS NULL) OR
        (is_seen = true  AND seen_time IS NOT NULL)
    )
);