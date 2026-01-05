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

### Watchlist (guild)
- vrc.watchchannel [#channel]     (set notify channel; default = current channel)
- vrc.watch [usr_... | @member]   (add to watchlist; default = yourself if linked)
- vrc.unwatch [usr_... | @member] (remove)
- vrc.watchlist                   (show list)
- vrc.watchclear                  (clear list)

Notes:
- Owner must set VRChat creds: vrc.setcreds <username> <password>
- Credentials are stored in Red config (plaintext). Use a dedicated bot account.
- If account requires 2FA, Basic login may fail. Use an account without 2FA or extend for 2FA.
