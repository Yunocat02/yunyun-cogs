# Wynncraft Red-DiscordBot Cog

A Red-DiscordBot cog for retrieving public Wynncraft data through the Wynncraft API v3.  
This cog provides utility commands for player profiles, characters, guilds, territories, items, leaderboards, map markers, and online player monitoring.

## Features

### Player Commands

- View Wynncraft player profiles
- Display character information
- Check online status and visible server/world information

### Guild Commands

- View guild information by guild name
- View guild information by guild prefix
- List guild directory entries
- Display online guild members when available

### Territory Commands

- List current territory ownership
- Filter territories by guild name or prefix
- View details for a specific territory

### Item and Search Commands

- Search items from the Wynncraft item database
- Display basic item information, requirements, and identifications
- Use Wynncraft global search for public resources

### Leaderboard Commands

- List available leaderboard types
- Display leaderboard entries by type

### Map Commands

- List Wynncraft map markers
- Search map markers by name

### Online Watch Commands

- Configure a Discord channel for player online alerts
- Add or remove players from a guild watch list
- Enable or disable online monitoring per Discord server
- Manually run an online watch check

## Requirements

- Red-DiscordBot 3.5.0 or later
- Python 3.8 or later
- `aiohttp`

The `aiohttp` dependency is declared in `info.json`.

## Installation

Place the `wynncraft` folder inside a Red cog path.

Example structure:

```text
red-cogs/
└── wynncraft/
    ├── README.md
    ├── __init__.py
    ├── info.json
    └── wynncraft.py
```

Add the cog path to Red:

```text
[p]addpath /path/to/red-cogs
```

Load the cog:

```text
[p]load wynncraft
```

If installing through a cog repository, use the standard Red repository commands:

```text
[p]repo add <repo_name> <repo_url>
[p]cog install <repo_name> wynncraft
[p]load wynncraft
```

## Command Overview

Use your bot prefix in place of `[p]`.

### General

```text
[p]wynn
```

Displays the main Wynncraft command list.

### Player

```text
[p]wynn player <username_or_uuid>
[p]wynn chars <username_or_uuid>
```

Examples:

```text
[p]wynn player Salted
[p]wynn chars Salted
```

### Online Players

```text
[p]wynn online
[p]wynn online <world>
```

Examples:

```text
[p]wynn online
[p]wynn online WC1
```

### Guild

```text
[p]wynn guild <guild_name>
[p]wynn guildprefix <prefix>
[p]wynn guildlist [limit]
```

Examples:

```text
[p]wynn guild Spectral Cabbage
[p]wynn guildprefix SPC
[p]wynn guildlist 20
```

### Territories

```text
[p]wynn territories
[p]wynn territories <guild_name_or_prefix>
[p]wynn territory <territory_name>
```

Examples:

```text
[p]wynn territories
[p]wynn territories SPC
[p]wynn territory Detlas
```

### Items and Search

```text
[p]wynn item <item_name>
[p]wynn search <query>
```

Examples:

```text
[p]wynn item Idol
[p]wynn search Detlas
```

### Leaderboards

```text
[p]wynn lbtypes
[p]wynn lb <leaderboard_type> [limit]
```

Examples:

```text
[p]wynn lbtypes
[p]wynn lb total-level 10
```

### Map Markers

```text
[p]wynn markers
[p]wynn markers <query>
```

Examples:

```text
[p]wynn markers
[p]wynn markers Detlas
```

## Online Watch Commands

The online watch system allows a Discord server to monitor selected Wynncraft players and send alerts when their visible online status changes.

### Enable or Disable Watch

```text
[p]wynnwatch enable
[p]wynnwatch disable
```

### Configure Alert Channel

```text
[p]wynnwatch channel
[p]wynnwatch channel #channel-name
```

If no channel is provided, the current channel is used.

### Manage Watch List

```text
[p]wynnwatch add <username>
[p]wynnwatch remove <username>
[p]wynnwatch list
```

Examples:

```text
[p]wynnwatch add Salted
[p]wynnwatch remove Salted
[p]wynnwatch list
```

### Set Watch Interval

```text
[p]wynnwatch interval <seconds>
```

Example:

```text
[p]wynnwatch interval 300
```

### Manual Watch Check

```text
[p]wynnwatch check
```

Runs a manual online status check for the configured watch list.

## API Token

The cog can be used without an API token.  
If you have a Wynncraft API token, the bot owner can configure it with:

```text
[p]wynn settoken <token>
```

To remove the token:

```text
[p]wynn cleartoken
```

These commands are restricted to the bot owner.

## Cache Management

The cog uses an in-memory cache to reduce repeated API requests.

To clear the cache manually:

```text
[p]wynn clearcache
```

This command requires administrator or Manage Server permissions.

## Permissions

### Bot Owner Only

```text
[p]wynn settoken
[p]wynn cleartoken
```

### Administrator or Manage Server

```text
[p]wynn clearcache
[p]wynnwatch enable
[p]wynnwatch disable
[p]wynnwatch channel
[p]wynnwatch add
[p]wynnwatch remove
[p]wynnwatch interval
[p]wynnwatch check
```

### Public Commands

```text
[p]wynn
[p]wynn player
[p]wynn chars
[p]wynn online
[p]wynn guild
[p]wynn guildprefix
[p]wynn guildlist
[p]wynn territories
[p]wynn territory
[p]wynn item
[p]wynn search
[p]wynn lbtypes
[p]wynn lb
[p]wynn markers
[p]wynnwatch list
```

## Data Source

This cog uses the public Wynncraft API v3:

```text
https://api.wynncraft.com/v3
```

The API provides public game, player, guild, item, leaderboard, map, and related data.

## Notes

- Some player data may be unavailable due to Wynncraft privacy or API visibility rules.
- Online player lists may not include every player name even when the total count is available.
- API responses may change over time; commands are designed to handle missing fields where possible.
- This cog does not store Wynncraft account credentials.
- The optional API token, if configured, is stored through Red's configuration system.

## File Structure

```text
wynncraft/
├── README.md
├── __init__.py
├── info.json
└── wynncraft.py
```

## License

No license is provided by default.  
Add a license file if you intend to distribute this cog publicly.
