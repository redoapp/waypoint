# CockroachDB Support

Waypoint supports CockroachDB alongside PostgreSQL as a database backend.

## Dialect Detection

Waypoint automatically detects whether the backend is PostgreSQL or CockroachDB by querying `SELECT version()` on the first connection. No configuration change is needed.

## Minimum Version

CockroachDB v24.3 or later is recommended.

## Key Differences from PostgreSQL

### No Automatic Role Cleanup

Waypoint does not automatically clean up expired roles. Instead, roles accumulate in the database. This is safe because:

- Passwords are rotated on every `EnsureUser` call, so expired roles cannot authenticate
- Roles only receive CONNECT and explicitly granted permissions
- The `revalidateLoop` in the proxy terminates connections when ACL permissions are revoked

### Manual Cleanup

If role accumulation becomes a concern, operators can manually drop idle `wp_*` roles:

```sql
-- List all Waypoint-managed roles
SELECT username FROM system.users WHERE username LIKE 'wp_%';

-- Drop a specific role (CockroachDB)
DROP ROLE IF EXISTS wp_alice_laptop_appdb;
```

For PostgreSQL backends:

```sql
-- List all Waypoint-managed roles
SELECT rolname FROM pg_roles WHERE rolname LIKE 'wp_%';

-- Drop a specific role
REASSIGN OWNED BY wp_alice_laptop_appdb TO CURRENT_USER;
DROP OWNED BY wp_alice_laptop_appdb;
DROP ROLE IF EXISTS wp_alice_laptop_appdb;
```

### Locking

Waypoint uses Redis-based distributed locks (via `SET NX EX`) instead of PostgreSQL advisory locks. This works identically on both backends and provides cross-instance coordination.
