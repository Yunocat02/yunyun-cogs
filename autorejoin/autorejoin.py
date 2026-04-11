from __future__ import annotations

import asyncio
import logging
from typing import Optional

import discord
import lavalink
from redbot.core import commands, Config

log = logging.getLogger("red.autorejoin")

# ─────────────────────────────────────────────────────────────
# Constants
# ─────────────────────────────────────────────────────────────

CHECK_INTERVAL = 10          # watchdog interval
REJOIN_DELAY = 3.0           # after bot is kicked/moved
CONNECT_TIMEOUT = 15.0       # lavalink connect/move timeout
RETRY_COOLDOWN = 20.0        # cooldown after connect/reconnect attempt
TRANSITION_GRACE = 15.0      # when player exists but channel_id is still None


class AutoRejoin(commands.Cog):
    """
    Auto-Rejoin Voice using Red Audio / Lavalink.

    Keeps the bot locked to a configured voice channel by ensuring a Lavalink
    player exists and is attached to the correct voice channel.

    This version avoids opening a native Discord voice connection directly,
    so it will not conflict with Red Audio / TTS / Lavalink players.
    """

    def __init__(self, bot):
        self.bot = bot
        self.config = Config.get_conf(
            self, identifier=20260411_01, force_registration=True
        )
        self.config.register_guild(
            enabled=False,
            channel_id=None,   # target voice channel ID
        )

        self._locks: dict[int, asyncio.Lock] = {}
        self._cooldown_until: dict[int, float] = {}
        self._pending_rejoin: set[int] = set()
        self._last_state_log: dict[int, str] = {}

        self._watchdog_task: Optional[asyncio.Task] = asyncio.create_task(
            self._watchdog_loop()
        )

    # ──────────────────────────────────────────
    # Helpers
    # ──────────────────────────────────────────

    def _get_lock(self, guild_id: int) -> asyncio.Lock:
        if guild_id not in self._locks:
            self._locks[guild_id] = asyncio.Lock()
        return self._locks[guild_id]

    def _now(self) -> float:
        return asyncio.get_running_loop().time()

    def _in_cooldown(self, guild_id: int) -> bool:
        return self._now() < self._cooldown_until.get(guild_id, 0)

    def _set_cooldown(self, guild_id: int, seconds: float) -> None:
        self._cooldown_until[guild_id] = self._now() + seconds

    def _clear_state_log(self, guild_id: int) -> None:
        self._last_state_log.pop(guild_id, None)

    def _log_state_once(self, guild_id: int, state: str, message: str, *args) -> None:
        """
        Prevent repeated identical info logs every watchdog tick.
        """
        if self._last_state_log.get(guild_id) != state:
            self._last_state_log[guild_id] = state
            log.info(message, *args)

    def _get_target_channel(
        self, guild: discord.Guild, channel_id: Optional[int]
    ) -> Optional[discord.VoiceChannel]:
        if channel_id is None:
            return None
        ch = guild.get_channel(channel_id)
        return ch if isinstance(ch, discord.VoiceChannel) else None

    def _get_ll_player(self, guild_id: int):
        try:
            return lavalink.get_player(guild_id)
        except Exception:
            return None

    async def _disconnect_player_safely(self, guild: discord.Guild) -> None:
        player = self._get_ll_player(guild.id)
        if player is None:
            return
        try:
            await player.disconnect()
        except Exception:
            log.exception("[%s] Failed to disconnect Lavalink player", guild.name)

    async def _lavalink_connect(
        self, guild: discord.Guild, channel: discord.VoiceChannel
    ) -> bool:
        """
        Ensure a Lavalink player exists and is connected to the target channel.

        Rules:
        - No player          -> lavalink.connect(channel)
        - Player channel=None -> transition state; do not spam move
        - Player wrong ch     -> player.move_to(channel)
        - Player already ok   -> do nothing
        """
        lock = self._get_lock(guild.id)
        if lock.locked():
            return False

        async with lock:
            self._pending_rejoin.add(guild.id)
            try:
                player = self._get_ll_player(guild.id)

                # Case 1: no player yet
                if player is None:
                    log.info("[%s] No Lavalink player — connecting to %s", guild.name, channel.name)
                    await asyncio.wait_for(
                        lavalink.connect(channel, self_deaf=True),
                        timeout=CONNECT_TIMEOUT,
                    )
                    self._set_cooldown(guild.id, RETRY_COOLDOWN)
                    self._clear_state_log(guild.id)
                    return True

                current_channel_id = getattr(player, "channel_id", None)
                is_connected_attr = getattr(player, "is_connected", False)
                is_connected = bool(
                    is_connected_attr() if callable(is_connected_attr) else is_connected_attr
                )

                # Case 2: already in correct channel and connected
                if is_connected and current_channel_id == channel.id:
                    self._clear_state_log(guild.id)
                    return True

                # Case 3: player exists but still in transition/not fully ready
                # Avoid move spam while channel_id is still None
                if current_channel_id is None:
                    self._log_state_once(
                        guild.id,
                        "transition-none",
                        "[%s] Lavalink player exists but channel is not ready yet — waiting",
                        guild.name,
                    )
                    self._set_cooldown(guild.id, TRANSITION_GRACE)
                    return False

                # Case 4: connected to another channel -> move
                log.info(
                    "[%s] Moving Lavalink player from %s to %s",
                    guild.name,
                    current_channel_id,
                    channel.id,
                )
                await asyncio.wait_for(player.move_to(channel), timeout=CONNECT_TIMEOUT)
                self._set_cooldown(guild.id, RETRY_COOLDOWN)
                self._clear_state_log(guild.id)
                return True

            except asyncio.TimeoutError:
                log.warning("[%s] Timed out while connecting/moving Lavalink player to %s", guild.name, channel.name)
                self._set_cooldown(guild.id, RETRY_COOLDOWN)
                return False
            except Exception as exc:
                log.exception("[%s] Lavalink rejoin failed for %s: %s", guild.name, channel.name, exc)
                self._set_cooldown(guild.id, RETRY_COOLDOWN)
                return False
            finally:
                self._pending_rejoin.discard(guild.id)

    async def _ensure_in_channel(self, guild: discord.Guild):
        cfg = self.config.guild(guild)
        if not await cfg.enabled():
            return

        if guild.id in self._pending_rejoin or self._in_cooldown(guild.id):
            return

        channel_id: Optional[int] = await cfg.channel_id()
        channel = self._get_target_channel(guild, channel_id)
        if channel is None:
            if channel_id is not None:
                log.warning("[%s] Configured channel %s not found or not a voice channel.", guild.name, channel_id)
            return

        player = self._get_ll_player(guild.id)

        # No player at all -> connect
        if player is None:
            self._log_state_once(
                guild.id,
                "missing-player",
                "[%s] Lavalink player missing — rejoining %s",
                guild.name,
                channel.name,
            )
            await self._lavalink_connect(guild, channel)
            return

        current_channel_id = getattr(player, "channel_id", None)
        is_connected_attr = getattr(player, "is_connected", False)
        is_connected = bool(
            is_connected_attr() if callable(is_connected_attr) else is_connected_attr
        )

        # Transitional state: player exists but channel_id not ready yet
        if current_channel_id is None:
            self._log_state_once(
                guild.id,
                "transition-none",
                "[%s] Lavalink player is still transitioning — skip retry for now",
                guild.name,
            )
            self._set_cooldown(guild.id, TRANSITION_GRACE)
            return

        # Wrong channel / disconnected
        if (not is_connected) or (current_channel_id != channel.id):
            self._log_state_once(
                guild.id,
                f"wrong-channel:{current_channel_id}:{is_connected}",
                "[%s] Not in target channel via Lavalink — rejoining %s",
                guild.name,
                channel.name,
            )
            await self._lavalink_connect(guild, channel)
            return

        # Healthy state
        self._clear_state_log(guild.id)

    # ──────────────────────────────────────────
    # Background watchdog
    # ──────────────────────────────────────────

    async def _watchdog_loop(self):
        try:
            await self.bot.wait_until_red_ready()
        except AttributeError:
            await self.bot.wait_until_ready()

        while True:
            try:
                await asyncio.sleep(CHECK_INTERVAL)
                for guild in self.bot.guilds:
                    await self._ensure_in_channel(guild)
            except asyncio.CancelledError:
                raise
            except Exception as exc:
                log.exception("Watchdog error: %s", exc)

    def cog_unload(self):
        if self._watchdog_task and not self._watchdog_task.done():
            self._watchdog_task.cancel()

    # ──────────────────────────────────────────
    # Discord event — instant rejoin trigger
    # ──────────────────────────────────────────

    @commands.Cog.listener()
    async def on_voice_state_update(
        self,
        member: discord.Member,
        before: discord.VoiceState,
        after: discord.VoiceState,
    ):
        """
        Detect when the bot itself leaves the target channel and trigger a Lavalink rejoin.
        """
        if not self.bot.user or member.id != self.bot.user.id:
            return

        guild = member.guild
        cfg = self.config.guild(guild)
        if not await cfg.enabled():
            return

        channel_id: Optional[int] = await cfg.channel_id()
        if channel_id is None:
            return

        was_in_target = before.channel is not None and before.channel.id == channel_id
        now_in_target = after.channel is not None and after.channel.id == channel_id

        if was_in_target and not now_in_target:
            log.info(
                "[%s] Bot left target channel (before=%s, after=%s) — scheduling Lavalink rejoin",
                guild.name,
                getattr(before.channel, "name", None),
                getattr(after.channel, "name", None),
            )
            self._set_cooldown(guild.id, REJOIN_DELAY)
            await asyncio.sleep(REJOIN_DELAY)
            await self._ensure_in_channel(guild)

    # ──────────────────────────────────────────
    # Commands
    # ──────────────────────────────────────────

    @commands.group(name="autorejoin", aliases=["arj"])
    @commands.guild_only()
    @commands.admin_or_permissions(manage_guild=True)
    async def autorejoin(self, ctx: commands.Context):
        """Auto-Rejoin Voice Channel using Lavalink."""

    @autorejoin.command(name="setup")
    async def autorejoin_setup(
        self,
        ctx: commands.Context,
        channel: discord.VoiceChannel,
    ):
        """Set the voice channel the bot should always stay in."""
        await self.config.guild(ctx.guild).channel_id.set(channel.id)
        await ctx.send(
            f"✅ Target voice channel set to **{channel.name}** (`{channel.id}`).\n"
            f"Use `{ctx.clean_prefix}autorejoin enable` to activate auto-rejoin."
        )

    @autorejoin.command(name="enable")
    async def autorejoin_enable(self, ctx: commands.Context):
        """Enable auto-rejoin for this server using Lavalink."""
        cfg = self.config.guild(ctx.guild)
        channel_id: Optional[int] = await cfg.channel_id()
        if channel_id is None:
            await ctx.send(
                f"⚠️ No voice channel configured yet. "
                f"Run `{ctx.clean_prefix}autorejoin setup <channel>` first."
            )
            return

        channel = self._get_target_channel(ctx.guild, channel_id)
        if channel is None:
            await ctx.send(
                "⚠️ The configured channel no longer exists. "
                f"Please run `{ctx.clean_prefix}autorejoin setup <channel>` again."
            )
            return

        await cfg.enabled.set(True)
        self._clear_state_log(ctx.guild.id)
        await ctx.send(f"▶️ Auto-rejoin **enabled** — joining **{channel.name}** through Lavalink now…")

        ok = await self._lavalink_connect(ctx.guild, channel)
        if not ok:
            await ctx.send(
                "⚠️ Could not connect through Lavalink right now. "
                "The watchdog will keep retrying automatically."
            )

    @autorejoin.command(name="disable")
    async def autorejoin_disable(self, ctx: commands.Context):
        """Disable auto-rejoin and disconnect Lavalink player."""
        cfg = self.config.guild(ctx.guild)
        await cfg.enabled.set(False)

        self._cooldown_until.pop(ctx.guild.id, None)
        self._pending_rejoin.discard(ctx.guild.id)
        self._clear_state_log(ctx.guild.id)

        await self._disconnect_player_safely(ctx.guild)
        await ctx.send("⏹️ Auto-rejoin **disabled**. Lavalink player has left the voice channel.")

    @autorejoin.command(name="status")
    async def autorejoin_status(self, ctx: commands.Context):
        """Show the current auto-rejoin configuration."""
        cfg = self.config.guild(ctx.guild)
        enabled: bool = await cfg.enabled()
        channel_id: Optional[int] = await cfg.channel_id()

        channel_name = "*(not set)*"
        if channel_id is not None:
            ch = ctx.guild.get_channel(channel_id)
            channel_name = f"**{ch.name}** (`{channel_id}`)" if ch else f"*(deleted: `{channel_id}`)*"

        player = self._get_ll_player(ctx.guild.id)
        if player:
            current_channel_id = getattr(player, "channel_id", None)
            is_connected_attr = getattr(player, "is_connected", False)
            is_connected = bool(
                is_connected_attr() if callable(is_connected_attr) else is_connected_attr
            )

            if is_connected and current_channel_id:
                current_ch = ctx.guild.get_channel(current_channel_id)
                in_channel = f"**{current_ch.name}**" if current_ch else f"`{current_channel_id}`"
            elif current_channel_id is None:
                in_channel = "*transitioning / pending*"
            else:
                in_channel = "*not connected*"
        else:
            in_channel = "*not connected*"

        state = "🟢 **ON**" if enabled else "🔴 **OFF**"

        embed = discord.Embed(
            title="Auto-Rejoin Status",
            colour=discord.Colour.green() if enabled else discord.Colour.red(),
        )
        embed.add_field(name="State", value=state, inline=True)
        embed.add_field(name="Target channel", value=channel_name, inline=True)
        embed.add_field(name="Currently in", value=in_channel, inline=True)
        embed.set_footer(text=f"Check interval: every {CHECK_INTERVAL}s")
        await ctx.send(embed=embed)

    @autorejoin.command(name="clear")
    async def autorejoin_clear(self, ctx: commands.Context):
        """Clear the configured channel and disable auto-rejoin."""
        cfg = self.config.guild(ctx.guild)
        was_enabled: bool = await cfg.enabled()

        await cfg.enabled.set(False)
        await cfg.channel_id.set(None)

        self._cooldown_until.pop(ctx.guild.id, None)
        self._pending_rejoin.discard(ctx.guild.id)
        self._clear_state_log(ctx.guild.id)

        if was_enabled:
            await self._disconnect_player_safely(ctx.guild)

        await ctx.send("🗑️ Auto-rejoin configuration cleared.")
