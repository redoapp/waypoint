---
title: Example Policies
description: Common ACL patterns for Waypoint.
sidebar:
  order: 2
---

## Backend team gets readwrite on their app, readonly on everything else

```json
{
  "grants": [{
    "src": ["group:backend"],
    "dst": ["tag:waypoint"],
    "cap": {
      "redo.com/cap/waypoint": [{
        "limits": {
          "max_conns": 10,
          "max_conn_duration": "1h"
        },
        "backends": {
          "pg-main": {
            "pg": {
              "databases": {
                "myapp":   { "permissions": ["readwrite"], "schemas": ["public", "app"] },
                "*":       { "permissions": ["readonly"] }
              }
            }
          }
        }
      }]
    }
  }]
}
```

## Data team gets readonly on analytics, no other access

```json
{
  "grants": [{
    "src": ["group:data"],
    "dst": ["tag:waypoint"],
    "cap": {
      "redo.com/cap/waypoint": [{
        "backends": {
          "pg-main": {
            "pg": {
              "databases": {
                "analytics": { "permissions": ["readonly"], "schemas": ["public"] }
              }
            }
          }
        }
      }]
    }
  }]
}
```

## Admin emergency access (high limits, all databases)

```json
{
  "grants": [{
    "src": ["group:dba"],
    "dst": ["tag:waypoint"],
    "cap": {
      "redo.com/cap/waypoint": [{
        "limits": { "max_conns": 50 },
        "backends": {
          "pg-main": {
            "pg": {
              "databases": {
                "*": { "permissions": ["admin"] }
              }
            }
          }
        }
      }]
    }
  }]
}
```

## TCP listener — flat access

For TCP listeners there's no per-database grammar; an empty object is the whole grant:

```json
{
  "grants": [{
    "src": ["group:ops"],
    "dst": ["tag:waypoint"],
    "cap": {
      "redo.com/cap/waypoint": [{
        "limits": { "max_conns": 5 },
        "backends": { "raw-mysql": {} }
      }]
    }
  }]
}
```

## MongoDB with mixed presets

For database-mode provisioning, the grammar is the same shape as Postgres:

```json
{
  "backends": {
    "mongo-prod": {
      "mongodb": {
        "databases": {
          "app":   { "permissions": ["readwrite"] },
          "logs":  { "permissions": ["readonly"] }
        }
      }
    }
  }
}
```

For [static-user mode](/waypoint/listeners/mongodb/#mode--static-atlas-compatible), the grant shape is identical — Waypoint picks the matching pre-configured user based on the resolved preset set.
