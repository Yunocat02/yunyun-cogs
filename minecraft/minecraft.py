from __future__ import annotations

import asyncio
import base64
import io
import json
import logging
import re
import struct
import time
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple

import discord
from redbot.core import commands, Config

log = logging.getLogger("red.minecraft")

DEFAULT_PORT = 25565
MIN_POLL_INTERVAL = 10


# ─────────────────────────────────────────────────────────────
# Minecraft Java Edition Server List Ping (SLP) implementation
# No external dependencies — uses raw asyncio TCP sockets.
# ─────────────────────────────────────────────────────────────

def _pack_varint(value: int) -> bytes:
    """Encode an integer as a Minecraft VarInt (unsigned 32-bit)."""
    out = bytearray()
    value &= 0xFFFFFFFF  # treat as unsigned 32-bit
    while True:
        b = value & 0x7F
        value >>= 7
        if value:
            b |= 0x80
        out.append(b)
        if not value:
            break
    return bytes(out)


def _pack_string(s: str) -> bytes:
    """Length-prefix a UTF-8 string with a VarInt."""
    data = s.encode("utf-8")
    return _pack_varint(len(data)) + data


def _pack_packet(packet_id: int, payload: bytes = b"") -> bytes:
    """Wrap packet_id + payload into a length-prefixed Minecraft packet."""
    body = _pack_varint(packet_id) + payload
    return _pack_varint(len(body)) + body


async def _read_varint_stream(reader: asyncio.StreamReader) -> int:
    """Read a VarInt from an asyncio StreamReader."""
    result = 0
    shift = 0
    while True:
        raw = await reader.readexactly(1)
        b = raw[0]
        result |= (b & 0x7F) << shift
        shift += 7
        if not (b & 0x80):
            break
        if shift >= 35:
            raise ValueError("VarInt too large")
    return result


def _read_varint_bytes(data: bytes, offset: int) -> Tuple[int, int]:
    """Read a VarInt from a bytes buffer. Returns (value, new_offset)."""
    result = 0
    shift = 0
    while offset < len(data):
        b = data[offset]
        offset += 1
        result |= (b & 0x7F) << shift
        shift += 7
        if not (b & 0x80):
            break
        if shift >= 35:
            raise ValueError("VarInt too large")
    return result, offset


_MC_FORMAT_RE = re.compile(r"§[0-9a-fk-orA-FK-OR]")


def _strip_mc_formatting(text: str) -> str:
    """Strip Minecraft color and format codes (§X)."""
    return _MC_FORMAT_RE.sub("", text)


def _parse_motd(description: Any) -> str:
    """
    Convert a Minecraft chat component (dict or str) to plain text.
    Handles both legacy strings and modern JSON chat objects.
    """
    if isinstance(description, str):
        return _strip_mc_formatting(description).strip()
    if isinstance(description, dict):
        parts: List[str] = []
        text = str(description.get("text") or "")
        if text:
            parts.append(text)
        for item in description.get("extra") or []:
            if isinstance(item, str):
                parts.append(item)
            elif isinstance(item, dict):
                parts.append(str(item.get("text") or ""))
        return _strip_mc_formatting("".join(parts)).strip()
    return _strip_mc_formatting(str(description)).strip()


class MCStatus:
    """Result of a Minecraft server status query."""

    __slots__ = (
        "online", "host", "port", "latency_ms",
        "version", "protocol",
        "motd", "players_online", "players_max", "player_names",
        "favicon_bytes",  # raw PNG bytes decoded from base64, or None
        "error",
    )

    def __init__(self):
        self.online: bool = False
        self.host: str = ""
        self.port: int = DEFAULT_PORT
        self.latency_ms: Optional[float] = None
        self.version: Optional[str] = None
        self.protocol: Optional[int] = None
        self.motd: Optional[str] = None
        self.players_online: Optional[int] = None
        self.players_max: Optional[int] = None
        self.player_names: List[str] = []
        self.favicon_bytes: Optional[bytes] = None
        self.error: Optional[str] = None


async def query_java_server(host: str, port: int, timeout: float = 8.0) -> MCStatus:
    """
    Query a Minecraft Java Edition server using the Server List Ping protocol.
    Returns an MCStatus object regardless of whether the server is reachable.
    """
    status = MCStatus()
    status.host = host
    status.port = port

    # ── Connect ─────────────────────────────────────────────────────────────
    try:
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(host, port),
            timeout=timeout,
        )
    except asyncio.TimeoutError:
        status.error = "Connection timed out"
        return status
    except OSError as exc:
        status.error = str(exc)
        return status

    try:
        # ── Handshake (C→S) ─────────────────────────────────────────────────
        # Fields: Protocol Version (VarInt) | Host (String) | Port (u16) | Next State (VarInt=1)
        handshake_payload = (
            _pack_varint(0)              # protocol version 0 (accepted for status)
            + _pack_string(host)
            + struct.pack(">H", port)
            + _pack_varint(1)            # next state = 1 (status)
        )
        writer.write(_pack_packet(0x00, handshake_payload))

        # ── Status Request (C→S) ─────────────────────────────────────────────
        writer.write(_pack_packet(0x00, b""))

        t0 = time.perf_counter()
        await writer.drain()

        # ── Status Response (S→C) ────────────────────────────────────────────
        length = await asyncio.wait_for(_read_varint_stream(reader), timeout=timeout)
        raw = await asyncio.wait_for(reader.readexactly(length), timeout=timeout)
        t1 = time.perf_counter()
        status.latency_ms = round((t1 - t0) * 1000, 1)

        # Parse packet from raw bytes
        packet_id, offset = _read_varint_bytes(raw, 0)
        if packet_id != 0x00:
            status.error = f"Unexpected packet ID 0x{packet_id:02X}"
            return status

        # Read JSON string (VarInt length + UTF-8)
        str_len, offset = _read_varint_bytes(raw, offset)
        json_str = raw[offset: offset + str_len].decode("utf-8")
        data = json.loads(json_str)

        # ── Parse response fields ─────────────────────────────────────────────
        status.online = True

        version_obj = data.get("version") or {}
        status.version = version_obj.get("name")
        status.protocol = version_obj.get("protocol")

        desc = data.get("description")
        if desc is not None:
            motd = _parse_motd(desc)
            status.motd = motd or None

        players_obj = data.get("players") or {}
        status.players_online = players_obj.get("online")
        status.players_max = players_obj.get("max")
        sample = players_obj.get("sample") or []
        status.player_names = [
            p.get("name", "") for p in sample
            if isinstance(p, dict) and p.get("name")
        ]

        # favicon is "data:image/png;base64,<b64>" — decode to raw bytes
        favicon_str = data.get("favicon")
        if isinstance(favicon_str, str) and "," in favicon_str:
            try:
                b64_part = favicon_str.split(",", 1)[1]
                status.favicon_bytes = base64.b64decode(b64_part)
            except Exception:
                pass

    except asyncio.TimeoutError:
        if not status.online:
            status.error = "Timed out waiting for response"
    except (json.JSONDecodeError, UnicodeDecodeError) as exc:
        status.error = f"Invalid server response: {exc}"
    except Exception as exc:
        status.error = str(exc)
    finally:
        try:
            writer.close()
            await writer.wait_closed()
        except Exception:
            pass

    return status


# ─────────────────────────────────────────────────────────────
# Cog
# ─────────────────────────────────────────────────────────────

class MinecraftCog(commands.Cog):
    """
    Minecraft server monitor for Red-DiscordBot.

    Per-guild: set a server IP:port, choose a notification channel, then
    enable monitoring. The bot polls the server on a background loop and
    posts embeds whenever players join/leave or the server goes offline/online.
    """

    def __init__(self, bot):
        self.bot = bot
        self.config = Config.get_conf(self, identifier=20260319_01, force_registration=True)

        self.config.register_global(
            poll_interval_sec=30,
        )
        self.config.register_guild(
            server_host=None,
            server_port=DEFAULT_PORT,
            notify_channel_id=None,
            monitoring_enabled=False,
            # Tracking state (persisted across restarts)
            last_online=None,          # True / False / None (unknown)
            last_player_count=None,    # int / None
            last_players=[],           # list[str] (names from sample)
        )

        self._poll_task: Optional[asyncio.Task] = asyncio.create_task(self._poll_loop())

    def cog_unload(self):
        if self._poll_task and not self._poll_task.done():
            self._poll_task.cancel()

    # ──────────────────────────────────────────
    # Background polling loop
    # ──────────────────────────────────────────

    async def _wait_ready(self):
        try:
            await self.bot.wait_until_red_ready()
        except Exception:
            await self.bot.wait_until_ready()

    async def _poll_loop(self):
        await self._wait_ready()
        while True:
            try:
                interval = await self.config.poll_interval_sec()
                interval = max(MIN_POLL_INTERVAL, int(interval or MIN_POLL_INTERVAL))
                await self._poll_all_guilds()
                await asyncio.sleep(interval)
            except asyncio.CancelledError:
                break
            except Exception as exc:
                log.exception("Poll loop error: %s", exc)
                await asyncio.sleep(30)

    async def _poll_all_guilds(self):
        for guild in list(self.bot.guilds):
            try:
                await self._poll_guild(guild)
            except Exception:
                continue

    async def _poll_guild(self, guild: discord.Guild):
        gconf = self.config.guild(guild)

        if not await gconf.monitoring_enabled():
            return

        host = await gconf.server_host()
        if not host:
            return

        ch_id = await gconf.notify_channel_id()
        if not ch_id:
            return

        channel = guild.get_channel(int(ch_id))
        if channel is None:
            return

        port = int(await gconf.server_port() or DEFAULT_PORT)
        status = await query_java_server(host, port)

        last_online = await gconf.last_online()
        last_players: List[str] = list(await gconf.last_players() or [])
        last_count: Optional[int] = await gconf.last_player_count()

        # ── First check after enable/restart — establish baseline ────────────
        if last_online is None:
            await gconf.last_online.set(status.online)
            await gconf.last_players.set(status.player_names)
            await gconf.last_player_count.set(status.players_online)
            return

        # ── Server state transitions ─────────────────────────────────────────
        if not status.online and last_online:
            embed = discord.Embed(
                title="🔴 Server Offline",
                description=f"**{host}:{port}** is unreachable.",
                color=discord.Color.red(),
                timestamp=datetime.now(timezone.utc),
            )
            if status.error:
                embed.add_field(name="Reason", value=f"`{status.error[:256]}`", inline=False)
            embed.set_footer(text="Minecraft Monitor")
            try:
                await channel.send(embed=embed)
            except Exception:
                pass
            await gconf.last_online.set(False)
            await gconf.last_players.set([])
            await gconf.last_player_count.set(None)
            return

        if status.online and not last_online:
            embed = discord.Embed(
                title="🟢 Server Back Online",
                description=f"**{host}:{port}** is reachable again!",
                color=discord.Color.green(),
                timestamp=datetime.now(timezone.utc),
            )
            if status.version:
                embed.add_field(name="Version", value=f"`{status.version}`", inline=True)
            if status.players_online is not None:
                embed.add_field(
                    name="Players",
                    value=f"`{status.players_online}/{status.players_max or '?'}`",
                    inline=True,
                )
            if status.latency_ms is not None:
                embed.add_field(name="Ping", value=f"`{status.latency_ms:.1f} ms`", inline=True)
            if status.motd:
                embed.add_field(name="MOTD", value=status.motd[:512], inline=False)
            embed.set_footer(text="Minecraft Monitor")
            try:
                await channel.send(embed=embed)
            except Exception:
                pass
            # Fall through to save state and check players below

        # ── Player join / leave detection ────────────────────────────────────
        if status.online:
            current_count = status.players_online or 0
            current_names = set(status.player_names)
            old_names = set(last_players)

            # "Full list" = sample contains exactly as many names as online count
            sample_is_full = (
                status.players_online is not None
                and len(status.player_names) == status.players_online
            )
            last_sample_was_full = (
                last_count is not None
                and len(last_players) == last_count
            )

            if sample_is_full and last_sample_was_full:
                # ── Name-level tracking ──────────────────────────────────────
                joined = sorted(current_names - old_names)
                left = sorted(old_names - current_names)

                if joined:
                    names_str = ", ".join(f"**{n}**" for n in joined)
                    embed = discord.Embed(
                        title=f"➕ {'Player' if len(joined) == 1 else 'Players'} Joined",
                        description=names_str,
                        color=discord.Color.green(),
                        timestamp=datetime.now(timezone.utc),
                    )
                    embed.set_footer(text=f"{host}:{port}  •  {current_count}/{status.players_max or '?'} players")
                    try:
                        await channel.send(embed=embed)
                    except Exception:
                        pass

                if left:
                    names_str = ", ".join(f"**{n}**" for n in left)
                    embed = discord.Embed(
                        title=f"➖ {'Player' if len(left) == 1 else 'Players'} Left",
                        description=names_str,
                        color=discord.Color.orange(),
                        timestamp=datetime.now(timezone.utc),
                    )
                    embed.set_footer(text=f"{host}:{port}  •  {current_count}/{status.players_max or '?'} players")
                    try:
                        await channel.send(embed=embed)
                    except Exception:
                        pass

            elif last_count is not None:
                # ── Count-level tracking (sample incomplete) ─────────────────
                # NOTE: On large servers the sample is a random ~12-name subset
                # that rotates every ping. We cannot derive who actually joined/left
                # from sample diffs, so we only report the count change.
                if current_count > last_count:
                    diff = current_count - last_count
                    embed = discord.Embed(
                        title=f"➕ {diff} Player{'s' if diff != 1 else ''} Joined",
                        description=(
                            f"Player count: **{last_count}** → **{current_count}**"
                            f"/{status.players_max or '?'}"
                        ),
                        color=discord.Color.green(),
                        timestamp=datetime.now(timezone.utc),
                    )
                    embed.set_footer(text=f"{host}:{port}  •  Minecraft Monitor")
                    try:
                        await channel.send(embed=embed)
                    except Exception:
                        pass

                elif current_count < last_count:
                    diff = last_count - current_count
                    embed = discord.Embed(
                        title=f"➖ {diff} Player{'s' if diff != 1 else ''} Left",
                        description=(
                            f"Player count: **{last_count}** → **{current_count}**"
                            f"/{status.players_max or '?'}"
                        ),
                        color=discord.Color.orange(),
                        timestamp=datetime.now(timezone.utc),
                    )
                    embed.set_footer(text=f"{host}:{port}  •  Minecraft Monitor")
                    try:
                        await channel.send(embed=embed)
                    except Exception:
                        pass

        # ── Save state ───────────────────────────────────────────────────────
        await gconf.last_online.set(status.online)
        if status.online:
            await gconf.last_players.set(status.player_names)
            await gconf.last_player_count.set(status.players_online)
        else:
            await gconf.last_players.set([])
            await gconf.last_player_count.set(None)

    # ──────────────────────────────────────────
    # Embed builders
    # ──────────────────────────────────────────

    def _build_status_embed(
        self,
        status: MCStatus,
        *,
        title_prefix: str = "",
    ) -> Tuple[discord.Embed, Optional[discord.File]]:
        """
        Returns (embed, file_or_None).
        If the server sent a favicon, `file` is a discord.File("favicon.png")
        and the embed thumbnail is set to "attachment://favicon.png".
        Send with: await channel.send(embed=embed, file=file)
        """
        favicon_file: Optional[discord.File] = None

        if not status.online:
            em = discord.Embed(
                title="🔴 Server Offline",
                description=status.error or "Could not reach server.",
                color=discord.Color.red(),
                timestamp=datetime.now(timezone.utc),
            )
            em.set_footer(text=f"{status.host}:{status.port}  •  Minecraft Monitor")
            return em, None

        prefix = f"{title_prefix} " if title_prefix else ""
        em = discord.Embed(
            title=f"{prefix}🟢 {status.host}:{status.port}",
            color=discord.Color.green(),
            timestamp=datetime.now(timezone.utc),
        )
        if status.motd:
            em.description = status.motd[:512]

        if status.version:
            em.add_field(name="🎮 Version", value=f"`{status.version}`", inline=True)

        if status.players_online is not None:
            player_count = f"`{status.players_online}/{status.players_max or '?'}`"
            em.add_field(name="👥 Players", value=player_count, inline=True)

        if status.latency_ms is not None:
            em.add_field(name="📶 Ping", value=f"`{status.latency_ms:.1f} ms`", inline=True)

        if status.player_names:
            is_sample = (
                status.players_online is not None
                and len(status.player_names) < status.players_online
            )
            names_str = "\n".join(f"• {n}" for n in status.player_names[:30])
            label = "🧑 Online Players (sample)" if is_sample else "🧑 Online Players"
            em.add_field(name=label, value=names_str[:1024], inline=False)
            footer_extra = "⚠️  Server returns a partial player list.  •  " if is_sample else ""
            em.set_footer(text=f"{footer_extra}Minecraft Monitor")
        elif status.players_online == 0:
            em.add_field(name="🧑 Online Players", value="*No players online.*", inline=False)
            em.set_footer(text="Minecraft Monitor")
        else:
            em.set_footer(text="Minecraft Monitor")

        # Attach favicon as thumbnail
        if status.favicon_bytes:
            try:
                favicon_file = discord.File(
                    io.BytesIO(status.favicon_bytes), filename="favicon.png"
                )
                em.set_thumbnail(url="attachment://favicon.png")
            except Exception:
                favicon_file = None

        return em, favicon_file

    # ──────────────────────────────────────────
    # Command group
    # ──────────────────────────────────────────

    @commands.group(name="mc", invoke_without_command=True)
    async def mc(self, ctx: commands.Context):
        """Minecraft server monitor command group."""
        await ctx.invoke(self.mc_help)

    @mc.command(name="help")
    async def mc_help(self, ctx: commands.Context):
        """Show an overview of Minecraft monitor commands."""
        em = discord.Embed(
            title="🎮 Minecraft Server Monitor",
            color=discord.Color.green(),
        )
        em.description = (
            "**Server Info**\n"
            "• `mc status` — query server status right now\n"
            "• `mc players` — list online players\n\n"
            "**Setup  (Admin / Manage Server)**\n"
            "• `mc set <host> [port]` — set the server address (default port: 25565)\n"
            "• `mc channel [#channel]` — set notification channel (defaults to current)\n"
            "• `mc enable` — enable monitoring & join/leave notifications\n"
            "• `mc disable` — disable monitoring & stop notifications\n"
            "• `mc reset` — reset tracking state (re-establishes baseline on next poll)\n"
            "• `mc info` — show current config\n\n"
            "**Poll Interval  (Bot Owner)**\n"
            "• `mc interval <seconds>` — set polling interval in seconds (min 10s)\n\n"
            "**Notes**\n"
            "• Works with Minecraft Java Edition servers only.\n"
            "• Player names are tracked by name when the server exposes a full sample list.\n"
            "  For large servers (typically 12+ players) only a count diff is reported.\n"
        )
        await ctx.send(embed=em)

    # ── Setup commands (Admin) ────────────────────────────────────────────────

    @mc.command(name="set")
    @commands.guild_only()
    @commands.admin_or_permissions(manage_guild=True)
    async def mc_set(self, ctx: commands.Context, host: str, port: int = DEFAULT_PORT):
        """Admin. Set the Minecraft server address to monitor.

        Examples:
          mc set mc.hypixel.net
          mc set play.myserver.com 25565
          mc set 192.168.1.10 25566
        """
        host = host.strip().lower()
        if port < 1 or port > 65535:
            return await ctx.send("❌ Invalid port. Must be between 1 and 65535.")

        gconf = self.config.guild(ctx.guild)
        await gconf.server_host.set(host)
        await gconf.server_port.set(port)
        # Reset tracking so the next poll establishes a clean baseline
        await gconf.last_online.set(None)
        await gconf.last_players.set([])
        await gconf.last_player_count.set(None)
        await ctx.send(f"✅ Server set to `{host}:{port}`. Tracking state reset.")

    @mc.command(name="channel")
    @commands.guild_only()
    @commands.admin_or_permissions(manage_guild=True)
    async def mc_channel(
        self,
        ctx: commands.Context,
        channel: Optional[discord.TextChannel] = None,
    ):
        """Admin. Set the channel where notifications will be sent (defaults to current channel)."""
        channel = channel or ctx.channel
        await self.config.guild(ctx.guild).notify_channel_id.set(int(channel.id))
        await ctx.send(f"✅ Notification channel set to {channel.mention}.")

    @mc.command(name="enable")
    @commands.guild_only()
    @commands.admin_or_permissions(manage_guild=True)
    async def mc_enable(self, ctx: commands.Context):
        """Admin. Enable server monitoring and join/leave notifications."""
        gconf = self.config.guild(ctx.guild)

        host = await gconf.server_host()
        if not host:
            return await ctx.send(
                "❌ No server configured. Run `mc set <host> [port]` first."
            )

        # Auto-set channel if none chosen yet
        ch_id = await gconf.notify_channel_id()
        if not ch_id:
            await gconf.notify_channel_id.set(int(ctx.channel.id))
            ch_id = ctx.channel.id

        await gconf.monitoring_enabled.set(True)
        # Reset tracking so the first poll just establishes baseline (no false alerts)
        await gconf.last_online.set(None)
        await gconf.last_players.set([])
        await gconf.last_player_count.set(None)

        port = await gconf.server_port() or DEFAULT_PORT
        ch = ctx.guild.get_channel(int(ch_id))
        await ctx.send(
            f"✅ Monitoring **enabled** for `{host}:{port}`.\n"
            f"Notifications → {ch.mention if ch else f'channel `{ch_id}`'}."
        )

    @mc.command(name="disable")
    @commands.guild_only()
    @commands.admin_or_permissions(manage_guild=True)
    async def mc_disable(self, ctx: commands.Context):
        """Admin. Disable server monitoring and stop all notifications."""
        await self.config.guild(ctx.guild).monitoring_enabled.set(False)
        await ctx.send("✅ Monitoring **disabled**. No more notifications will be sent.")

    @mc.command(name="reset")
    @commands.guild_only()
    @commands.admin_or_permissions(manage_guild=True)
    async def mc_reset(self, ctx: commands.Context):
        """Admin. Reset tracking state. The next poll will re-establish a fresh baseline without sending alerts."""
        gconf = self.config.guild(ctx.guild)
        await gconf.last_online.set(None)
        await gconf.last_players.set([])
        await gconf.last_player_count.set(None)
        await ctx.send("✅ Tracking state reset. The next poll will establish a new baseline.")

    @mc.command(name="info")
    @commands.guild_only()
    @commands.admin_or_permissions(manage_guild=True)
    async def mc_info(self, ctx: commands.Context):
        """Admin. Show current monitoring configuration for this guild."""
        gconf = self.config.guild(ctx.guild)

        host = await gconf.server_host()
        port = await gconf.server_port() or DEFAULT_PORT
        ch_id = await gconf.notify_channel_id()
        enabled = await gconf.monitoring_enabled()
        interval = await self.config.poll_interval_sec()
        last_online = await gconf.last_online()
        last_count = await gconf.last_player_count()
        last_players: List[str] = list(await gconf.last_players() or [])

        em = discord.Embed(title="⚙️ Minecraft Monitor Config", color=discord.Color.blurple())

        em.add_field(
            name="Server",
            value=f"`{host}:{port}`" if host else "*(not set)*",
            inline=True,
        )
        em.add_field(
            name="Monitoring",
            value="✅ Enabled" if enabled else "❌ Disabled",
            inline=True,
        )
        em.add_field(name="Poll Interval", value=f"`{interval}s`", inline=True)

        ch = ctx.guild.get_channel(int(ch_id)) if ch_id else None
        em.add_field(
            name="Notify Channel",
            value=ch.mention if ch else "*(not set)*",
            inline=True,
        )

        if last_online is None:
            status_str = "*(not checked yet)*"
        else:
            status_str = "🟢 Online" if last_online else "🔴 Offline"
        em.add_field(name="Last Known Status", value=status_str, inline=True)

        if last_count is not None:
            em.add_field(name="Last Known Count", value=str(last_count), inline=True)

        if last_players:
            names_preview = ", ".join(last_players[:20])
            if len(last_players) > 20:
                names_preview += f" +{len(last_players) - 20} more"
            em.add_field(name="Last Known Players", value=names_preview, inline=False)

        await ctx.send(embed=em)

    # ── Info commands (any member) ───────────────────────────────────────────

    @mc.command(name="status")
    @commands.guild_only()
    async def mc_status(self, ctx: commands.Context):
        """Query the configured Minecraft server's current status."""
        gconf = self.config.guild(ctx.guild)
        host = await gconf.server_host()
        if not host:
            return await ctx.send(
                "❌ No server configured. Ask an admin to run `mc set <host> [port]`."
            )

        port = int(await gconf.server_port() or DEFAULT_PORT)

        async with ctx.typing():
            status = await query_java_server(host, port)

        embed, favicon_file = self._build_status_embed(status)
        if favicon_file:
            await ctx.send(embed=embed, file=favicon_file)
        else:
            await ctx.send(embed=embed)

    @mc.command(name="players")
    @commands.guild_only()
    async def mc_players(self, ctx: commands.Context):
        """Show the list of online players on the configured server."""
        gconf = self.config.guild(ctx.guild)
        host = await gconf.server_host()
        if not host:
            return await ctx.send(
                "❌ No server configured. Ask an admin to run `mc set <host> [port]`."
            )

        port = int(await gconf.server_port() or DEFAULT_PORT)

        async with ctx.typing():
            status = await query_java_server(host, port)

        embed, favicon_file = self._build_status_embed(status)
        if favicon_file:
            await ctx.send(embed=embed, file=favicon_file)
        else:
            await ctx.send(embed=embed)

    # ── Owner commands ────────────────────────────────────────────────────────

    @mc.command(name="interval")
    @commands.is_owner()
    async def mc_interval(self, ctx: commands.Context, seconds: int):
        """Owner only. Set the global server polling interval in seconds (minimum 10s).

        This affects all guilds. Setting it too low may cause rate-limiting on
        servers that block frequent pings.
        """
        seconds = max(MIN_POLL_INTERVAL, seconds)
        await self.config.poll_interval_sec.set(seconds)
        await ctx.send(f"✅ Poll interval set to `{seconds}s` (applies to all guilds).")
