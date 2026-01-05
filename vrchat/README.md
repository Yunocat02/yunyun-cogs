# VRChat Cog for Red-DiscordBot

A VRChat utility cog for Red-DiscordBot:
- Fetch user/world details by ID
- Search users/worlds with a dropdown to open details
- World-only “Show Author Profile”
- Guild watchlist notifications (state/status/location changes)
- Supports VRChat 2FA (TOTP / Email OTP) via interactive button + modal

---

## Commands

### Core
- `vrc help` — show help
- `vrc uid <usr_...>` — fetch user by VRChat userId
- `vrc user <display name>` — search users (up to 60) + dropdown details
- `vrc wid <wrld_...>` — fetch world by worldId (includes world-only “Show Author Profile”)
- `vrc world <world name>` — search worlds (up to 60) + dropdown details (includes world-only “Show Author Profile”)
- `vrc link` — link Discord ↔ VRChat userId (button + modal)
- `vrc me` — show your linked VRChat profile
- `vrc profile @member` — show a member’s linked VRChat profile

### Owner-only
- `vrc setcreds <username> <password>` — set VRChat login credentials
- `vrc clearcookie` — clear VRChat auth cookie
- `vrc 2fa` — open the 2FA verification UI (buttons + modal)
- `vrc watchinterval <seconds>` — set watch interval (min 20s)

### Watchlist (guild admin / manage_guild)
- `vrc watchchannel [#channel]` — set notification channel (default: current channel)
- `vrc watch [usr_... | @member]` — add to watchlist (default: yourself if linked)
- `vrc unwatch [usr_... | @member]` — remove from watchlist
- `vrc watchlist` — show watchlist
- `vrc watchclear` — clear watchlist

---

## Notes & Security

- The owner must run `vrc setcreds <username> <password>` first.
- Credentials are stored in Red config (plaintext). Use a dedicated VRChat bot account.
- If VRChat returns **HTTP 401: Requires Two-Factor Authentication**, run `vrc 2fa`
  (or click the provided 2FA button) and enter the code (TOTP or Email OTP).
