# Minecraft Server Monitor

Monitor a Minecraft **Java Edition** server from Discord.  
No extra Python packages required — uses the native Server List Ping (SLP) protocol over TCP.

---

## Features

| Feature | Description |
|---|---|
| **Live status** | Query version, MOTD, online player count, and ping on demand |
| **Player list** | Show who's currently online (full list for ≤12-ish players, sample/count for larger servers) |
| **Join / Leave alerts** | Posts an embed in the chosen channel whenever players join or leave |
| **Server up / down alerts** | Notifies when the server goes offline or comes back online |
| **Per-guild config** | Each guild sets its own server address, notification channel, and toggle |
| **Enable / Disable** | Turn monitoring on or off at any time without losing your settings |
| **No dependencies** | Pure asyncio TCP — nothing to `pip install` |

---

## Quick Setup

```
mc set play.myserver.com        ← set server (port defaults to 25565)
mc channel #mc-notifications    ← choose where to send alerts
mc enable                       ← start monitoring
```

---

## Command Reference

### Server Info  *(any member)*

| Command | Description |
|---|---|
| `mc status` | Query server status right now (version, MOTD, player count, ping) |
| `mc players` | List currently online players |

### Setup  *(Admin / Manage Server)*

| Command | Description |
|---|---|
| `mc set <host> [port]` | Set the server address. Port defaults to `25565`. |
| `mc channel [#channel]` | Set the notification channel. Defaults to the current channel. |
| `mc enable` | Enable monitoring and start sending join/leave/online/offline notifications. |
| `mc disable` | Disable monitoring. Settings are kept; run `mc enable` to resume. |
| `mc reset` | Reset tracking state so the next poll re-establishes a fresh baseline (clears false-alert risk after downtime). |
| `mc info` | Show current config and last known server state for this guild. |

### Bot Owner

| Command | Description |
|---|---|
| `mc interval <seconds>` | Set the global polling interval (minimum 10s, default 30s). Applies to all guilds. |

---

## How Player Tracking Works

The Minecraft SLP response includes a **sample** of online players.

- If the sample contains **all** online players (`sample_size == online_count`), the bot tracks **individual names** and reports exactly who joined or left.
- If the server only returns a **partial sample** (common on large/popular servers), the bot falls back to **count-based** tracking ("2 players joined") and includes any names it recognises from the sample.

Some servers disable the sample list entirely; in that case only the count is available.

---

## Limitations

- **Java Edition only.** Bedrock Edition uses a UDP-based Raknet protocol and is not supported.
- **SRV records** are not followed automatically (most servers use direct hostnames/IPs, which work fine).
- The bot must have permission to **Send Messages** and **Embed Links** in the configured notification channel.

---

## Example Notifications

**Player joined**
> ➕ **Steve** joined  
> `play.myserver.com:25565  •  4/20 players`

**Server offline**
> 🔴 Server Offline  
> `play.myserver.com:25565` is unreachable.

**Server back online**
> 🟢 Server Back Online  
> Version: `1.21.4`  •  Players: `1/20`  •  Ping: `12.3 ms`
