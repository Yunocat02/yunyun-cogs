# AutoRejoin

Keeps the bot permanently joined to a specific voice channel per Discord server.  
When the bot is kicked, disconnected, or moved away from the target channel it rejoins automatically.

---

## Features

- **Per-guild** — every server sets its own target channel and toggle independently.
- **Default OFF** — feature is disabled until an admin explicitly enables it.
- **Instant rejoin** — uses `on_voice_state_update` to detect disconnects and reacts immediately.
- **Watchdog loop** — background task checks every 10 seconds as a safety net.
- **No external dependencies** — uses only `discord.py` / Red internals.

---

## Commands

All commands require **Manage Server** permission (or bot admin).

| Command | Description |
|---|---|
| `[p]autorejoin setup <channel>` | Set the voice channel the bot must stay in. |
| `[p]autorejoin enable` | Enable auto-rejoin for this server and join immediately. |
| `[p]autorejoin disable` | Disable auto-rejoin and disconnect the bot. |
| `[p]autorejoin status` | Show current state: enabled/disabled, target channel, current channel. |
| `[p]autorejoin clear` | Disable and remove the channel configuration entirely. |

Alias: `[p]arj` works everywhere `[p]autorejoin` does.

---

## Quick-start

```
[p]autorejoin setup #music-room
[p]autorejoin enable
```

---

## How it works

1. **`on_voice_state_update`** — whenever the bot's own voice state changes (disconnected / moved), the cog waits 3 seconds and then rejoins the target channel.
2. **Watchdog loop** — every 10 seconds it iterates over all guilds that have auto-rejoin enabled and verifies the bot is in the correct channel; if not, it rejoins.
3. A per-guild `asyncio.Lock` prevents multiple simultaneous connection attempts to the same guild.
