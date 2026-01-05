# VRChat Cog for Red-DiscordBot

## Commands
- vrc.help
- vrc.uid <usr_...>
- vrc.user <display name>  (search up to 60 + dropdown to open details)
- vrc.wid <wrld_...>
- vrc.world <world name>   (search up to 60 + dropdown to open details)
- vrc.link                 (button + modal to link your Discord -> VRChat userId)
- vrc.me
- vrc.profile @member
- vrc.2fa                  (Owner-only: open interactive 2FA verification UI if required)

### Watchlist (guild)
- vrc.watchchannel [#channel]     (set notify channel; default = current channel)
- vrc.watch [usr_... | @member]   (add to watchlist; default = yourself if linked)
- vrc.unwatch [usr_... | @member] (remove)
- vrc.watchlist                   (show list)
- vrc.watchclear                  (clear list)

## Setup
1) Owner must set VRChat creds:
- `vrc.setcreds <username> <password>`

2) If the VRChat account requires 2FA:
- Use `vrc.2fa` (Owner only), or
- Trigger any command (e.g., `vrc.user neko`) and the bot will show a button to enter the 2FA code.

Supported 2FA methods:
- TOTP (Authenticator App code)
- Email OTP (code sent to your email)

## Notes
- Credentials are stored in Red config (plaintext). Use a dedicated bot account.
- The 2FA UI is Owner-only to reduce risk.
