# yunyun-cogs
Redbot cogs for **Red-DiscordBot** authored by **yunyun**.

This repository provides a growing set of cogs designed for production use: clean UX, interactive components (dropdowns, buttons, modals), and practical workflows for real servers.

---

## Requirements
- **Red-DiscordBot v3** (minimum bot version may vary per cog)
- The built-in **Downloader** cog must be loaded

> Cog-specific minimum version: see each cog’s `info.json`.

---

## Installation

### 1) Load Downloader
Run on your Red instance:
```bash
[p]load downloader
````

### 2) Add this repository

```bash
[p]repo add yunyun-cogs https://github.com/Yunocat02/yunyun-cogs
```

### 3) Install a cog

```bash
[p]cog install yunyun-cogs <cog>
```

### 4) Load the cog

```bash
[p]load <cog>
```

### Update

Update all cogs from this repo:

```bash
[p]cog update yunyun-cogs
```

---

## Available cogs

### `vrchat`

**VRChat command group for Red-DiscordBot.**
Search users/worlds with a dropdown to open details, fetch by ID, link Discord↔VRChat ID, guild watchlist notifications, and interactive 2FA verification (TOTP/Email OTP).

**Highlights**

* User/world search with dropdown detail viewer
* Fetch by ID (`usr_...`, `wrld_...`)
* World detail view includes **World-only “Show Author Profile”** button
* Link Discord account ↔ VRChat userId (modal UI)
* Guild watchlist notifications (status/location/state changes)
* Supports VRChat 2FA (TOTP / Email OTP) via interactive button + modal

---

## Support / Issues

If you find a bug or want a feature request, open an issue:

* [https://github.com/Yunocat02/yunyun-cogs/issues](https://github.com/Yunocat02/yunyun-cogs/issues)

When reporting issues, include:

* Red version / Python version
* Cog version (commit hash if possible)
* Relevant logs (redbot logs + traceback)

---