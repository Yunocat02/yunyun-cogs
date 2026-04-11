from __future__ import annotations

import asyncio
import logging
from typing import Optional

import discord
import lavalink
from redbot.core import commands, Config

log = logging.getLogger("red.autorejoin")

CHECK_INTERVAL = 10
REJOIN_DELAY = 3.0
CONNECT_TIMEOUT = 15.0


class AutoRejoin(commands.Cog):
    """
    Auto-Rejoin Voice using Red Audio / Lavalink.
    Keeps the bot attached to a configured voice channel by creating or moving
    the Lavalink player instead of opening a native Discord voice connection.
    """

    def __init__(self, bot):
        self.bot = bot
        self.config = Config.get_conf(
            self, identifier=20260411_01, force_registration=True
        )
        self.config.register_guild(
            enabled=False,
            channel_id=None,
        )

        self._locks: dict[int, asyncio.Lock] = {}
        self._watchdog_task: Optional[asyncio.Task] = asyncio.create_task(
            self._watchdog_loop()
        )

    def _get_lock(self, guild_id: int) -> asyncio.Lock:
        if guild_id not in self._locks:
            self._locks[guild_id] = asyncio.Lock()
        return self._locks[guild_id]

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

    async def _lavalink_connect(
        self, guild: discord.Guild, channel: discord.VoiceChannel
    ) -> bool:
        """
        Ensure a Lavalink player exists and is connected to the target channel.
        """
        lock = self._get_lock(guild.id)
        if lock.locked():
            return False

        async with lock:
            try:
                player = self._get_ll_player(guild.id)

                # Case 1: no player yet -> create via Lavalink
                if player is None:
                    log.info("[%s] No Lavalink player — connecting to %s", guild.name, channel.name)
                    await asyncio.wait_for(
                        lavalink.connect(channel, self_deaf=True),
                        timeout=CONNECT_TIMEOUT,
                    )
                    return True

                # Case 2: player exists but wrong channel -> move via player
                current_channel_id = getattr(player, "channel_id", None)
                is_connected = bool(getattr(player, "is_connected", False))

                if current_channel_id == channel.id and is_connected:
                    return True

                log.info(
                    "[%s] Lavalink player not in target channel (current=%s, target=%s) — moving",
                    guild.name,
                    current_channel_id,
                    channel.id,
                )

                await asyncio.wait_for(player.move_to(channel), timeout=CONNECT_TIMEOUT)
                return True

            except asyncio.TimeoutError:
                log.warning("[%s] Timed out while connecting/moving Lavalink player to %s", guild.name, channel.name)
            except Exception as exc:
                log.exception("[%s] Lavalink rejoin failed for %s: %s", guild.name, channel.name, exc)
            return False

    async def _ensure_in_channel(self, guild: discord.Guild):
        cfg = self.config.guild(guild)
        if not await cfg.enabled():
            return

        channel_id: Optional[int] = await cfg.channel_id()
        channel = self._get_target_channel(guild, channel_id)
        if channel is None:
            if channel_id is not None:
                log.warning("[%s] Configured channel %s not found or not a voice channel.", guild.name, channel_id)
            return

        player = self._get_ll_player(guild.id)
        if player is None:
            log.info("[%s] Lavalink player missing — rejoining %s", guild.name, channel.name)
            await self._lavalink_connect(guild, channel)
            return

        current_channel_id = getattr(player, "channel_id", None)
        is_connected = bool(getattr(player, "is_connected", False))

        if (not is_connected) or (current_channel_id != channel.id):
            log.info("[%s] Not in target channel via Lavalink — rejoining %s", guild.name, channel.name)
            await self._lavalink_connect(guild, channel)

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

    @commands.Cog.listener()
    async def on_voice_state_update(
        self,
        member: discord.Member,
        before: discord.VoiceState,
        after: discord.VoiceState,
    ):
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
            await asyncio.sleep(REJOIN_DELAY)
            await self._ensure_in_channel(guild)

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
        await self.config.guild(ctx.guild).channel_id.set(channel.id)
        await ctx.send(
            f"✅ Target voice channel set to **{channel.name}** (`{channel.id}`).\n"
            f"Use `{ctx.clean_prefix}autorejoin enable` to activate auto-rejoin."
        )

    @autorejoin.command(name="enable")
    async def autorejoin_enable(self, ctx: commands.Context):
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
        await ctx.send(f"▶️ Auto-rejoin **enabled** — joining **{channel.name}** through Lavalink now…")

        ok = await self._lavalink_connect(ctx.guild, channel)
        if not ok:
            await ctx.send(
                "⚠️ Could not connect through Lavalink right now. "
                "The watchdog will keep retrying automatically."
            )

    @autorejoin.command(name="disable")
    async def autorejoin_disable(self, ctx: commands.Context):
        cfg = self.config.guild(ctx.guild)
        await cfg.enabled.set(False)

        player = self._get_ll_player(ctx.guild.id)
        if player is not None:
            try:
                await player.disconnect()
            except Exception:
                log.exception("[%s] Failed to disconnect Lavalink player", ctx.guild.name)

        await ctx.send("⏹️ Auto-rejoin **disabled**. Lavalink player has left the voice channel.")

    @autorejoin.command(name="status")
    async def autorejoin_status(self, ctx: commands.Context):
        cfg = self.config.guild(ctx.guild)
        enabled: bool = await cfg.enabled()
        channel_id: Optional[int] = await cfg.channel_id()

        channel_name = "*(not set)*"
        if channel_id is not None:
            ch = ctx.guild.get_channel(channel_id)
            channel_name = f"**{ch.name}** (`{channel_id}`)" if ch else f"*(deleted: `{channel_id}`)*"

        player = self._get_ll_player(ctx.guild.id)
        if player and getattr(player, "is_connected", False):
            current_channel_id = getattr(player, "channel_id", None)
            current_ch = ctx.guild.get_channel(current_channel_id) if current_channel_id else None
            in_channel = f"**{current_ch.name}**" if current_ch else f"`{current_channel_id}`"
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
        cfg = self.config.guild(ctx.guild)
        was_enabled: bool = await cfg.enabled()
        await cfg.enabled.set(False)
        await cfg.channel_id.set(None)

        if was_enabled:
            player = self._get_ll_player(ctx.guild.id)
            if player is not None:
                try:
                    await player.disconnect()
                except Exception:
                    log.exception("[%s] Failed to disconnect Lavalink player", ctx.guild.name)

        await ctx.send("🗑️ Auto-rejoin configuration cleared.")
