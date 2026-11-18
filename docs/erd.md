# Database design (ERD)

SecureShare uses 4 tables in PostgreSQL. The real file content is **not** in the database:
it is stored **encrypted** in MinIO. The database only keeps metadata and the *wrapped* (encrypted) file keys.

```mermaid
erDiagram
    users ||--o{ files : "owns"
    users ||--o{ share_links : "creates"
    files ||--o{ share_links : "is shared by"
    users |o--o{ audit_logs : "does"
    files |o--o{ audit_logs : "is target of"

    users {
        uuid id PK
        varchar email UK "unique, lowercase"
        varchar password_hash "argon2/bcrypt, never the password"
        boolean is_active
        timestamptz created_at
    }

    files {
        uuid id PK "random UUID, not guessable (anti-IDOR)"
        uuid owner_id FK
        varchar original_name "sanitized display name"
        varchar object_name UK "random name in MinIO"
        bigint size_bytes
        varchar mime_type "detected from magic bytes"
        bytea wrapped_key "file key encrypted by MASTER_KEY"
        bytea key_nonce "nonce used to wrap the key"
        bytea file_nonce "nonce used to encrypt the file"
        timestamptz created_at
    }

    share_links {
        uuid id PK
        uuid file_id FK
        uuid created_by FK
        varchar token_hash UK "SHA-256 of the token, never the token"
        varchar password_hash "optional"
        timestamptz expires_at
        int max_downloads "optional"
        int download_count
        timestamptz revoked_at "null = still active"
        timestamptz created_at
    }

    audit_logs {
        bigint id PK
        uuid user_id FK "null if anonymous / deleted"
        varchar action "LOGIN_SUCCESS, UPLOAD, DOWNLOAD, ..."
        uuid file_id FK "optional"
        varchar status "success / failure / denied"
        inet ip_address
        text user_agent
        jsonb details "extra info, NEVER secrets"
        timestamptz created_at
    }
```

## Relationships

| Relationship | Meaning | On delete |
|---|---|---|
| users → files | one user owns many files | delete user → delete their files |
| files → share_links | one file can have many links | delete file → delete its links |
| users → share_links | who created the link | delete user → delete their links |
| users → audit_logs | who did the action | delete user → **keep the log**, user_id = NULL |
| files → audit_logs | which file was touched | delete file → **keep the log**, file_id = NULL |

## Security decisions

| Decision | Threat it stops |
|---|---|
| UUID ids instead of 1, 2, 3... | **IDOR / enumeration**: an attacker cannot guess other files' ids |
| `password_hash` only | **DB leak**: real passwords are never stored |
| `token_hash` only (SHA-256) | **DB leak**: a stolen DB does not give working share links |
| `wrapped_key` (envelope encryption) | **DB leak**: file keys are useless without `MASTER_KEY` (kept in env, not in DB) |
| random `object_name` in MinIO | **Info leak**: file names in storage reveal nothing |
| audit logs kept when user/file is deleted | **Repudiation**: actions stay provable |
| `details` JSONB never contains secrets | **Sensitive data in logs** |
| `audit_logs` is append-only (no update/delete in the API) | **Log tampering** |
