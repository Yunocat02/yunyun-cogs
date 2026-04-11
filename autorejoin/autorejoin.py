from __future__ import annotations

import asyncio
import logging
from typing import Optional

import discord
from redbot.core import commands, Config
from redbot.core.utils.chat_formatting import box

log = logging.getLogger("red.autorejoin")

# ─────────────────────────────────────────────────────────────
# Constants
# ─────────────────────────────────────────────────────────────

CHECK_INTERVAL = 10          # seconds between each watchdog tick
REJOIN_DELAY   = 3.0         # seconds to wait before rejoining after a drop
CONNECT_TIMEOUT = 10.0       # seconds to wait for a voice connection


# ─────────────────────────────────────────────────────────────
# Cog
# ─────────────────────────────────────────────────────────────

class AutoRejoin(commands.Cog):
    """
    Auto-Rejoin Voice — keeps the bot locked to a configured voice channel.

    Per-guild: choose which voice channel the bot must stay in, then toggle
    the feature on/off. When enabled, the bot joins immediately and rejoins
    automatically whenever it is disconnected or moved away.
    """

    def __init__(self, bot):
        self.bot = bot
        self.config = Config.get_conf(
            self, identifier=20260411_01, force_registration=True
        )
        self.config.register_guild(
            enabled=False,
            channel_id=None,   # voice channel ID to stay in
        )

        # Per-guild asyncio lock — prevents concurrent rejoin attempts
        self._locks: dict[int, asyncio.Lock] = {}

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

    async def _guild_voice_client(self, guild: discord.Guild) -> Optional[discord.VoiceClient]:
        """Return the bot's VoiceClient for *guild*, or None."""
        return guild.voice_client  # type: ignore[return-value]

    async def _try_join(self, guild: discord.Guild, channel: discord.VoiceChannel) -> bool:
        """
        Join *channel* in *guild*.  If already connected to the wrong channel,
        move; if disconnected, connect fresh.  Returns True on success.
        """
        lock = self._get_lock(guild.id)
        if lock.locked():
            return False  # another rejoin is already in progress

        async with lock:
            try:
                vc: Optional[discord.VoiceClient] = guild.voice_client  # type: ignore
                if vc is not None:
                    if vc.channel.id == channel.id and vc.is_connected():
                        return True  # already in the right place
                    log.debug("[%s] Moving to %s", guild.name, channel.name)
                    await asyncio.wait_for(vc.move_to(channel), timeout=CONNECT_TIMEOUT)
                else:
                    log.debug("[%s] Connecting to %s", guild.name, channel.name)
                    await asyncio.wait_for(
                        channel.connect(reconnect=True), timeout=CONNECT_TIMEOUT
                    )
                return True
            except asyncio.TimeoutError:
                log.warning("[%s] Timed out while joining %s", guild.name, channel.name)
            except discord.ClientException as exc:
                log.warning("[%s] ClientException joining %s: %s", guild.name, channel.name, exc)
            except Exception as exc:
                log.exception("[%s] Unexpected error joining %s: %s", guild.name, channel.name, exc)
            return False

    async def _ensure_in_channel(self, guild: discord.Guild):
        """Check whether the bot is in the configured channel; rejoin if not."""
        cfg = self.config.guild(guild)
        if not await cfg.enabled():
            return

        channel_id: Optional[int] = await cfg.channel_id()
        if channel_id is None:
            return

        channel: Optional[discord.VoiceChannel] = guild.get_channel(channel_id)  # type: ignore
        if channel is None or not isinstance(channel, discord.VoiceChannel):
            log.warning("[%s] Configured channel %s not found or not a voice channel.", guild.name, channel_id)
            return

        vc: Optional[discord.VoiceClient] = guild.voice_client  # type: ignore
        if vc is None or not vc.is_connected() or vc.channel.id != channel_id:
            log.info("[%s] Not in target channel — rejoining %s", guild.name, channel.name)
            await self._try_join(guild, channel)

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
    # Discord event — instant rejoin
    # ──────────────────────────────────────────

    @commands.Cog.listener()
    async def on_voice_state_update(
        self,
        member: discord.Member,
        before: discord.VoiceState,
        after: discord.VoiceState,
    ):
        """Detect when the bot itself leaves a voice channel and rejoin at once."""
        if member.id != self.bot.user.id:
            return

        guild = member.guild
        cfg = self.config.guild(guild)
        if not await cfg.enabled():
            return

        channel_id: Optional[int] = await cfg.channel_id()
        if channel_id is None:
            return

        # Bot left or was moved away from the target channel
        was_in_target = before.channel is not None and before.channel.id == channel_id
        now_in_target = after.channel is not None and after.channel.id == channel_id

        if was_in_target and not now_in_target:
            log.info(
                "[%s] Bot left target channel (before=%s, after=%s) — scheduling rejoin",
                guild.name,
                before.channel,
                after.channel,
            )
            await asyncio.sleep(REJOIN_DELAY)
            await self._ensure_in_channel(guild)

    # ──────────────────────────────────────────
    # Commands
    # ──────────────────────────────────────────

    @commands.group(name="autorejoin", aliases=["arj"])
    @commands.guild_only()
    @commands.admin_or_permissions(manage_guild=True)
    async def autorejoin(self, ctx: commands.Context):
        """Auto-Rejoin Voice Channel — keep the bot locked to one voice channel."""

    # ── setup ────────────────────────────────

    @autorejoin.command(name="setup")
    async def autorejoin_setup(
        self,
        ctx: commands.Context,
        channel: discord.VoiceChannel,
    ):
        """Set the voice channel the bot should always stay in.

        Example: `[p]autorejoin setup #general-voice`
        """
        await self.config.guild(ctx.guild).channel_id.set(channel.id)
        await ctx.send(
            f"\u2705 Target voice channel set to **{channel.name}** (`{channel.id}`).\n"
            f"Use `{ctx.clean_prefix}autorejoin enable` to activate auto-rejoin."
        )

    # ── enable ───────────────────────────────

    @autorejoin.command(name="enable")
    async def autorejoin_enable(self, ctx: commands.Context):
        """Enable auto-rejoin for this server."""
        cfg = self.config.guild(ctx.guild)
        channel_id: Optional[int] = await cfg.channel_id()
        if channel_id is None:
            await ctx.send(
                f"\u26a0\ufe0f No voice channel configured yet. "
                f"Run `{ctx.clean_prefix}autorejoin setup <channel>` first."
            )
            return

        channel: Optional[discord.VoiceChannel] = ctx.guild.get_channel(channel_id)  # type: ignore
        if channel is None or not isinstance(channel, discord.VoiceChannel):
            await ctx.send(
                "\u26a0\ufe0f The configured channel no longer exists. "
                f"Please run `{ctx.clean_prefix}autorejoin setup <channel>` again."
            )
            return

        await cfg.enabled.set(True)
        await ctx.send(f"\u25b6\ufe0f Auto-rejoin **enabled** — joining **{channel.name}** now…")
        ok = await self._try_join(ctx.guild, channel)
        if not ok:
            await ctx.send(
                "\u26a0\ufe0f Could not connect right now. "
                "The watchdog will keep retrying automatically."
            )

    # ── disable ──────────────────────────────

    @autorejoin.command(name="disable")
    async def autorejoin_disable(self, ctx: commands.Context):
        """Disable auto-rejoin for this server.

        The bot will leave the voice channel and stop rejoining.
        """
        cfg = self.config.guild(ctx.guild)
        await cfg.enabled.set(False)

        vc: Optional[discord.VoiceClient] = ctx.guild.voice_client  # type: ignore
        if vc is not None and vc.is_connected():
            await vc.disconnect(force=False)

        await ctx.send("\u23f9\ufe0f Auto-rejoin **disabled**. Bot has left the voice channel.")

    # ── status ───────────────────────────────

    @autorejoin.command(name="status")
    async def autorejoin_status(self, ctx: commands.Context):
        """Show the current auto-rejoin configuration for this server."""
        cfg = self.config.guild(ctx.guild)
        enabled: bool = await cfg.enabled()
        channel_id: Optional[int] = await cfg.channel_id()

        channel_name = "*(not set)*"
        if channel_id is not None:
            ch = ctx.guild.get_channel(channel_id)
            channel_name = f"**{ch.name}** (`{channel_id}`)" if ch else f"*(deleted: `{channel_id}`)*"

        vc: Optional[discord.VoiceClient] = ctx.guild.voice_client  # type: ignore
        if vc and vc.is_connected():
            in_channel = f"**{vc.channel.name}**"
        else:
            in_channel = "*not connected*"

        state = "\U0001f7e2 **ON**" if enabled else "\U0001f534 **OFF**"

        embed = discord.Embed(
            title="Auto-Rejoin Status",
            colour=discord.Colour.green() if enabled else discord.Colour.red(),
        )
        embed.add_field(name="State", value=state, inline=True)
        embed.add_field(name="Target channel", value=channel_name, inline=True)
        embed.add_field(name="Currently in", value=in_channel, inline=True)
        embed.set_footer(text=f"Check interval: every {CHECK_INTERVAL}s")
        await ctx.send(embed=embed)

    # ── clear ────────────────────────────────

    @autorejoin.command(name="clear")
    async def autorejoin_clear(self, ctx: commands.Context):
        """Clear the configured channel and disable auto-rejoin for this server."""
        cfg = self.config.guild(ctx.guild)
        was_enabled: bool = await cfg.enabled()
        await cfg.enabled.set(False)
        await cfg.channel_id.set(None)

        vc: Optional[discord.VoiceClient] = ctx.guild.voice_client  # type: ignore
        if was_enabled and vc is not None and vc.is_connected():
            await vc.disconnect(force=False)

        await ctx.send("\U0001f5d1\ufe0f Auto-rejoin configuration cleared.")
