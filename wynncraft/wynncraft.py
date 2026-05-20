from __future__ import annotations

import asyncio
import logging
import time
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple
from urllib.parse import quote

import aiohttp
import discord
from redbot.core import Config, checks, commands


log = logging.getLogger("red.wynncraft")


class WynncraftAPIError(Exception):
    """Raised when Wynncraft API returns an error."""


class SimpleTTLCache:
    """Tiny in-memory TTL cache.

    This is intentionally simple because this cog is designed for low/moderate usage.
    It avoids extra dependencies and prevents repeated API calls when users run the same
    command several times in a short period.
    """

    def __init__(self, max_size: int = 256):
        self.max_size = max_size
        self._store: Dict[str, Tuple[float, Any]] = {}

    def get(self, key: str) -> Optional[Any]:
        item = self._store.get(key)
        if not item:
            return None

        expires_at, value = item
        if time.monotonic() >= expires_at:
            self._store.pop(key, None)
            return None

        return value

    def set(self, key: str, value: Any, ttl: int) -> None:
        if ttl <= 0:
            return

        if len(self._store) >= self.max_size:
            self.cleanup(force_one=True)

        self._store[key] = (time.monotonic() + ttl, value)

    def cleanup(self, *, force_one: bool = False) -> None:
        now = time.monotonic()
        expired = [key for key, (expires_at, _) in self._store.items() if expires_at <= now]

        for key in expired:
            self._store.pop(key, None)

        if force_one and len(self._store) >= self.max_size and self._store:
            oldest_key = min(self._store.items(), key=lambda item: item[1][0])[0]
            self._store.pop(oldest_key, None)

    def clear(self) -> None:
        self._store.clear()

    def __len__(self) -> int:
        self.cleanup()
        return len(self._store)


class Wynncraft(commands.Cog):
    """Wynncraft API v3 utility commands.

    Provides player, guild, territory, item, leaderboard, map marker,
    and online watch utilities for Red-DiscordBot.
    """

    BASE_URL = "https://api.wynncraft.com/v3"

    TTL_ONLINE = 60
    TTL_PLAYER = 180
    TTL_GUILD = 180
    TTL_TERRITORY = 30
    TTL_ITEMS = 3600
    TTL_LEADERBOARD = 900
    TTL_MARKERS = 3600
    TTL_SEARCH = 180

    def __init__(self, bot):
        self.bot = bot
        self.config = Config.get_conf(self, identifier=2026051802, force_registration=True)

        self.config.register_global(
            api_token=None,
            default_cache_seconds=120,
            watch_loop_sleep_seconds=60,
        )

        self.config.register_guild(
            watch_enabled=False,
            watch_channel_id=None,
            watch_players=[],
            watch_interval=300,
            watch_mode="alert",
            watch_board_message_id=None,
            watch_last_seen={},
            last_watch_check_ts=0.0,
            last_online_state={},
        )

        self._session: Optional[aiohttp.ClientSession] = None
        self._cache = SimpleTTLCache(max_size=256)
        self._watch_task: Optional[asyncio.Task] = None

    async def cog_load(self):
        """Start background task after cog is loaded."""
        if self._watch_task is None or self._watch_task.done():
            self._watch_task = asyncio.create_task(self._watch_loop())
            log.info("Wynncraft watch loop started.")

    async def cog_unload(self):
        """Cleanly stop background task and close HTTP session."""
        if self._watch_task:
            self._watch_task.cancel()
            try:
                await self._watch_task
            except asyncio.CancelledError:
                pass
            except Exception:
                log.exception("Unexpected error while stopping Wynncraft watch task.")
            finally:
                self._watch_task = None

        if self._session and not self._session.closed:
            await self._session.close()
            log.info("Wynncraft HTTP session closed.")

    async def _get_session(self) -> aiohttp.ClientSession:
        if self._session is None or self._session.closed:
            timeout = aiohttp.ClientTimeout(total=15)
            self._session = aiohttp.ClientSession(timeout=timeout)
        return self._session

    async def _headers(self) -> Dict[str, str]:
        headers = {
            "Accept": "application/json",
            "User-Agent": "Red-DiscordBot Wynncraft Cog/1.2",
        }

        token = await self.config.api_token()
        if token:
            headers["Authorization"] = f"Bearer {token}"

        return headers

    @staticmethod
    def _make_cache_key(path: str, params: Optional[Dict[str, Any]]) -> str:
        if not params:
            return f"{path}|"

        safe_items = tuple(sorted((str(key), repr(value)) for key, value in params.items()))
        return f"{path}|{safe_items}"

    async def _request(
        self,
        path: str,
        *,
        params: Optional[Dict[str, Any]] = None,
        ttl: Optional[int] = None,
        use_cache: bool = True,
    ) -> Any:
        """GET Wynncraft API with small TTL cache and clear errors."""
        if not path.startswith("/"):
            path = "/" + path

        if ttl is None:
            ttl = await self.config.default_cache_seconds()

        cache_key = self._make_cache_key(path, params)

        if use_cache:
            cached = self._cache.get(cache_key)
            if cached is not None:
                return cached

        session = await self._get_session()
        url = self.BASE_URL + path

        try:
            async with session.get(url, params=params, headers=await self._headers()) as resp:
                text = await resp.text()

                try:
                    data = await resp.json(content_type=None)
                except Exception:
                    data = {"detail": text}

                if resp.status == 429:
                    retry_after = resp.headers.get("Retry-After")
                    reset_after = resp.headers.get("RateLimit-Reset")
                    wait_hint = retry_after or reset_after or "a short while"
                    raise WynncraftAPIError(
                        f"Rate limited by Wynncraft API. Please retry after {wait_hint} seconds."
                    )

                if resp.status >= 400:
                    detail = data.get("detail") if isinstance(data, dict) else text
                    error = data.get("error") if isinstance(data, dict) else "APIError"
                    raise WynncraftAPIError(f"{resp.status} {error}: {detail}")

                if use_cache:
                    self._cache.set(cache_key, data, int(ttl or 0))

                return data

        except asyncio.TimeoutError as exc:
            raise WynncraftAPIError("Request timed out. Please try again later.") from exc
        except aiohttp.ClientError as exc:
            raise WynncraftAPIError(f"Network error: {exc}") from exc

    @staticmethod
    def _fmt_bool(value: Any) -> str:
        if value is True:
            return "🟢 Yes"
        if value is False:
            return "⚪ No"
        return "N/A"

    @staticmethod
    def _fmt_number(value: Any) -> str:
        if isinstance(value, (int, float)):
            return f"{value:,}"
        return str(value) if value is not None else "N/A"

    @staticmethod
    def _shorten(value: Any, limit: int = 1024) -> str:
        text = "N/A" if value is None else str(value)
        return text if len(text) <= limit else text[: limit - 3] + "..."

    @staticmethod
    def _embed(title: str, description: Optional[str] = None) -> discord.Embed:
        return discord.Embed(title=title, description=description, color=discord.Color.blue())

    async def _send_error(self, ctx: commands.Context, exc: Exception) -> None:
        await ctx.send(f"❌ Wynncraft API error: `{self._shorten(exc, 1800)}`")

    async def _send_embed(self, ctx: commands.Context, embed: discord.Embed) -> None:
        """Send an embed with a plain-text fallback when Embed Links is unavailable."""
        if ctx.guild and isinstance(ctx.channel, discord.TextChannel):
            me = ctx.guild.me
            if me is None and self.bot.user is not None:
                me = ctx.guild.get_member(self.bot.user.id)

            if me is not None:
                permissions = ctx.channel.permissions_for(me)
                if not permissions.embed_links:
                    parts = []
                    if embed.title:
                        parts.append(f"**{embed.title}**")
                    if embed.description:
                        parts.append(embed.description)

                    for field in embed.fields:
                        parts.append(f"**{field.name}**\n{field.value}")

                    fallback = "\n\n".join(parts) or "No content available."
                    return await ctx.send(self._shorten(fallback, 1900))

        await ctx.send(embed=embed)

    @staticmethod
    def _multi_selector_message(data: Dict[str, Any]) -> str:
        objects = data.get("objects", {})
        if isinstance(objects, dict) and objects:
            rows = [f"- `{key}`: {value}" for key, value in list(objects.items())[:10]]
            return "Multiple matches found. Please use a more specific query:\n" + "\n".join(rows)
        return "Multiple matches found. Please use a more specific query."

    @staticmethod
    def _flatten_guild_members(members: Dict[str, Any]) -> List[Tuple[str, str, Dict[str, Any]]]:
        rows: List[Tuple[str, str, Dict[str, Any]]] = []

        if not isinstance(members, dict):
            return rows

        ranks = ("owner", "chief", "strategist", "captain", "recruiter", "recruit")

        for rank in ranks:
            group = members.get(rank, {})
            if isinstance(group, dict):
                for name, meta in group.items():
                    rows.append((rank, name, meta if isinstance(meta, dict) else {}))

        return rows

    @commands.group(name="wynn", aliases=["wynncraft"], invoke_without_command=True)
    async def wynn(self, ctx: commands.Context):
        """Wynncraft API commands."""
        p = ctx.clean_prefix

        embed = self._embed("Wynncraft Commands")
        embed.description = (
            f"`{p}wynn player <username>` - player profile\n"
            f"`{p}wynn chars <username>` - player characters\n"
            f"`{p}wynn online [WC1]` - online players\n"
            f"`{p}wynn guild <name>` - guild by name\n"
            f"`{p}wynn guildprefix <prefix>` - guild by prefix\n"
            f"`{p}wynn guildlist [limit]` - guild directory\n"
            f"`{p}wynn territories [guild]` - territories\n"
            f"`{p}wynn territory <name>` - one territory\n"
            f"`{p}wynn item <name>` - item search\n"
            f"`{p}wynn search <query>` - global search\n"
            f"`{p}wynn lbtypes` / `{p}wynn lb <type>` - leaderboard\n"
            f"`{p}wynn markers [query]` - map markers\n"
            f"`{p}wynnwatch` - online watch commands"
        )

        await self._send_embed(ctx, embed)

    @wynn.command(name="settoken")
    @checks.is_owner()
    async def set_token(self, ctx: commands.Context, token: str):
        """Set optional Wynncraft API token.

        Security note:
        This command tries to delete the original Discord message to reduce token exposure.
        Prefer running this command in DM with the bot if your Redbot setup allows it.
        """
        await self.config.api_token.set(token)

        try:
            await ctx.message.delete()
        except discord.HTTPException:
            log.warning("Could not delete Wynncraft settoken command message.", exc_info=True)

        await ctx.send("✅ Wynncraft API token saved. The command message was deleted if permissions allowed.")

    @wynn.command(name="cleartoken")
    @checks.is_owner()
    async def clear_token(self, ctx: commands.Context):
        """Clear optional Wynncraft API token."""
        await self.config.api_token.clear()
        await ctx.send("✅ Wynncraft API token cleared.")

    @wynn.command(name="clearcache")
    @checks.admin_or_permissions(manage_guild=True)
    async def clear_cache(self, ctx: commands.Context):
        """Clear local API cache."""
        self._cache.clear()
        await ctx.send("✅ Wynncraft cache cleared.")

    @wynn.command(name="online")
    async def online(self, ctx: commands.Context, server: Optional[str] = None):
        """Show online players. Optionally filter by server/world, e.g. WC1."""
        params = {"identifier": "username"}

        if server:
            params["server"] = server

        try:
            data = await self._request("/player", params=params, ttl=self.TTL_ONLINE)
        except Exception as exc:
            return await self._send_error(ctx, exc)

        total = data.get("total", 0) if isinstance(data, dict) else 0
        players = data.get("players", {}) if isinstance(data, dict) else {}

        embed = self._embed(f"Wynncraft Online{f' - {server}' if server else ''}")
        embed.add_field(name="Total", value=self._fmt_number(total), inline=True)

        if isinstance(players, dict) and players:
            names = list(players.keys())[:25]
            embed.add_field(name="Visible players", value=", ".join(names), inline=False)

            if len(players) > 25:
                embed.set_footer(text=f"Showing 25 of {len(players)} visible players.")
        else:
            embed.add_field(
                name="Visible players",
                value="No visible players or hidden by privacy rules.",
                inline=False,
            )

        await self._send_embed(ctx, embed)

    @wynn.command(name="player")
    async def player(self, ctx: commands.Context, username_or_uuid: str):
        """Show player profile."""
        try:
            data = await self._request(
                f"/player/{quote(username_or_uuid, safe='')}",
                ttl=self.TTL_PLAYER,
            )
        except Exception as exc:
            return await self._send_error(ctx, exc)

        if isinstance(data, dict) and data.get("error") == "MultipleObjectsReturned":
            return await ctx.send(self._multi_selector_message(data))

        if not isinstance(data, dict):
            return await ctx.send("Unexpected player response.")

        embed = self._embed(f"Wynncraft Player: {data.get('username', username_or_uuid)}")
        embed.add_field(name="Online", value=self._fmt_bool(data.get("online")), inline=True)
        embed.add_field(name="Server", value=str(data.get("server") or "N/A"), inline=True)
        embed.add_field(
            name="Rank",
            value=str(data.get("rank") or data.get("supportRank") or "N/A"),
            inline=True,
        )

        guild = data.get("guild") or {}
        guild_text = "N/A"

        if isinstance(guild, dict):
            guild_text = guild.get("name") or guild.get("prefix") or "N/A"
        elif guild:
            guild_text = str(guild)

        embed.add_field(name="Guild", value=guild_text, inline=True)

        global_data = data.get("globalData") or {}
        if isinstance(global_data, dict):
            embed.add_field(
                name="Total Level",
                value=self._fmt_number(global_data.get("totalLevel")),
                inline=True,
            )
            embed.add_field(
                name="Playtime",
                value=f"{self._fmt_number(global_data.get('playtime'))} hrs",
                inline=True,
            )
            embed.add_field(
                name="Mobs Killed",
                value=self._fmt_number(global_data.get("mobsKilled")),
                inline=True,
            )
            embed.add_field(
                name="Chests Found",
                value=self._fmt_number(global_data.get("chestsFound")),
                inline=True,
            )
            embed.add_field(
                name="Wars",
                value=self._fmt_number(global_data.get("wars")),
                inline=True,
            )

        if data.get("uuid"):
            embed.set_footer(text=f"UUID: {data['uuid']}")

        await self._send_embed(ctx, embed)

    @wynn.command(name="chars", aliases=["characters"])
    async def characters(self, ctx: commands.Context, username_or_uuid: str):
        """List visible player characters."""
        try:
            data = await self._request(
                f"/player/{quote(username_or_uuid, safe='')}/characters",
                ttl=self.TTL_PLAYER,
            )
        except Exception as exc:
            return await self._send_error(ctx, exc)

        if isinstance(data, dict) and data.get("error") == "MultipleObjectsReturned":
            return await ctx.send(self._multi_selector_message(data))

        if not isinstance(data, dict) or not data:
            return await ctx.send("No visible characters found.")

        rows = []

        for _, char in list(data.items())[:15]:
            if not isinstance(char, dict):
                continue

            ctype = char.get("type", "UNKNOWN")
            reskin = char.get("reskin")
            label = f"{ctype}/{reskin}" if reskin else ctype
            level = char.get("level", "?")
            total = char.get("totalLevel", "?")
            modes = ", ".join(char.get("gamemode") or []) or "-"
            name = char.get("nickname") or label

            rows.append(f"**{name}** — {label} Lv.{level}, Total {total}, GM: {modes}")

        embed = self._embed(f"Characters: {username_or_uuid}", "\n".join(rows) or "No visible details.")

        if len(data) > 15:
            embed.set_footer(text=f"Showing 15 of {len(data)} characters.")

        await self._send_embed(ctx, embed)

    @wynn.command(name="guild")
    async def guild(self, ctx: commands.Context, *, guild_name: str):
        """Show guild by name."""
        await self._send_guild(ctx, guild_name, by_prefix=False)

    @wynn.command(name="guildprefix", aliases=["gprefix"])
    async def guild_prefix(self, ctx: commands.Context, prefix: str):
        """Show guild by prefix/tag."""
        await self._send_guild(ctx, prefix, by_prefix=True)

    async def _send_guild(self, ctx: commands.Context, query: str, *, by_prefix: bool):
        path = (
            f"/guild/prefix/{quote(query, safe='')}"
            if by_prefix
            else f"/guild/{quote(query, safe='')}"
        )

        try:
            data = await self._request(path, params={"identifier": "username"}, ttl=self.TTL_GUILD)
        except Exception as exc:
            return await self._send_error(ctx, exc)

        if isinstance(data, dict) and data.get("error") == "MultipleObjectsReturned":
            return await ctx.send(self._multi_selector_message(data))

        if not isinstance(data, dict):
            return await ctx.send("Unexpected guild response.")

        embed = self._embed(f"Guild: {data.get('name', query)} [{data.get('prefix', '?')}]")
        embed.add_field(name="Level", value=self._fmt_number(data.get("level")), inline=True)
        embed.add_field(name="XP %", value=self._fmt_number(data.get("xpPercent")), inline=True)
        embed.add_field(name="Territories", value=self._fmt_number(data.get("territories")), inline=True)
        embed.add_field(name="Wars", value=self._fmt_number(data.get("wars")), inline=True)
        embed.add_field(name="Raids", value=self._fmt_number(data.get("raids")), inline=True)
        embed.add_field(name="Online", value=self._fmt_number(data.get("online")), inline=True)

        members = data.get("members") or {}
        if isinstance(members, dict) and members.get("total") is not None:
            embed.add_field(name="Members", value=self._fmt_number(members.get("total")), inline=True)

        rows = self._flatten_guild_members(members)
        online_rows = [(rank, name) for rank, name, meta in rows if meta.get("online") is True]

        if online_rows:
            text = "\n".join(f"**{name}** ({rank})" for rank, name in online_rows[:12])
            embed.add_field(name="Online members", value=text, inline=False)
        else:
            embed.add_field(name="Online members", value="No visible online members.", inline=False)

        if data.get("created"):
            embed.set_footer(text=f"Created: {data.get('created')}")

        await self._send_embed(ctx, embed)

    @wynn.command(name="guildlist")
    async def guild_list(self, ctx: commands.Context, limit: int = 20):
        """List guild directory."""
        limit = max(1, min(limit, 50))

        try:
            data = await self._request("/guild/list/guild", ttl=3600)
        except Exception as exc:
            return await self._send_error(ctx, exc)

        if not isinstance(data, dict):
            return await ctx.send("Unexpected guild list response.")

        rows = []

        for name, meta in list(data.items())[:limit]:
            prefix = meta.get("prefix", "?") if isinstance(meta, dict) else "?"
            rows.append(f"**{name}** [{prefix}]")

        embed = self._embed("Wynncraft Guild Directory", "\n".join(rows) or "No guild found.")
        embed.set_footer(text=f"Showing {len(rows)} of {len(data)} guilds.")

        await self._send_embed(ctx, embed)

    @wynn.command(name="territories")
    async def territories(self, ctx: commands.Context, *, guild_filter: Optional[str] = None):
        """List territories, optionally filtered by guild name or prefix."""
        try:
            data = await self._request("/guild/list/territory", ttl=self.TTL_TERRITORY)
        except Exception as exc:
            return await self._send_error(ctx, exc)

        if not isinstance(data, dict):
            return await ctx.send("Unexpected territory response.")

        rows = []
        needle = guild_filter.lower() if guild_filter else None

        for territory, meta in data.items():
            guild = meta.get("guild", {}) if isinstance(meta, dict) else {}
            gname = guild.get("name", "?") if isinstance(guild, dict) else "?"
            prefix = guild.get("prefix", "?") if isinstance(guild, dict) else "?"

            if needle and needle not in gname.lower() and needle not in prefix.lower():
                continue

            rows.append(f"**{territory}** — {gname} [{prefix}]")

        title = "Wynncraft Territories" + (f" for {guild_filter}" if guild_filter else "")
        embed = self._embed(title, "\n".join(rows[:25]) or "No matching territories.")

        if len(rows) > 25:
            embed.set_footer(text=f"Showing 25 of {len(rows)} matching territories.")

        await self._send_embed(ctx, embed)

    @wynn.command(name="territory")
    async def territory(self, ctx: commands.Context, *, territory_name: str):
        """Show one territory owner."""
        try:
            data = await self._request("/guild/list/territory", ttl=self.TTL_TERRITORY)
        except Exception as exc:
            return await self._send_error(ctx, exc)

        if not isinstance(data, dict):
            return await ctx.send("Unexpected territory response.")

        needle = territory_name.lower()
        selected_name = None
        selected_meta = None

        for name, meta in data.items():
            if name.lower() == needle:
                selected_name, selected_meta = name, meta
                break

        if selected_meta is None:
            for name, meta in data.items():
                if needle in name.lower():
                    selected_name, selected_meta = name, meta
                    break

        if selected_meta is None:
            return await ctx.send("Territory not found.")

        guild = selected_meta.get("guild", {}) if isinstance(selected_meta, dict) else {}
        location = selected_meta.get("location", {}) if isinstance(selected_meta, dict) else {}

        embed = self._embed(f"Territory: {selected_name}")

        if isinstance(guild, dict):
            embed.add_field(
                name="Guild",
                value=f"{guild.get('name', '?')} [{guild.get('prefix', '?')}]",
                inline=True,
            )

        embed.add_field(name="Acquired", value=str(selected_meta.get("acquired", "N/A")), inline=False)

        if isinstance(location, dict):
            embed.add_field(
                name="Location",
                value=f"Start: {location.get('start')}\nEnd: {location.get('end')}",
                inline=False,
            )

        await self._send_embed(ctx, embed)

    @wynn.command(name="item")
    async def item(self, ctx: commands.Context, *, query: str):
        """Search item database."""
        try:
            data = await self._request(
                "/item/database",
                params={"fullResult": ""},
                ttl=self.TTL_ITEMS,
            )
        except Exception as exc:
            return await self._send_error(ctx, exc)

        candidates = self._extract_item_candidates(data)
        needle = query.lower()

        exact_matches = []
        partial_matches = []

        for item in candidates:
            if not isinstance(item, dict):
                continue

            name = item.get("displayName") or item.get("internalName") or item.get("name")
            if not name:
                continue

            lowered = name.lower()

            if lowered == needle:
                exact_matches.append(item)
            elif needle in lowered:
                partial_matches.append(item)

        results = exact_matches or partial_matches

        if not results:
            return await ctx.send("No item found.")

        item = results[0]
        name = item.get("displayName") or item.get("internalName") or query

        embed = self._embed(f"Item: {name}")
        embed.add_field(name="Type", value=str(item.get("type", "N/A")), inline=True)
        embed.add_field(name="SubType", value=str(item.get("subType", "N/A")), inline=True)
        embed.add_field(
            name="Tier/Rarity",
            value=str(item.get("rarity") or item.get("tier") or "N/A"),
            inline=True,
        )

        requirements = item.get("requirements")
        if isinstance(requirements, dict):
            level = requirements.get("level") or item.get("level")

            if level is not None:
                embed.add_field(name="Level", value=str(level), inline=True)

            req_rows = [f"{key}: {value}" for key, value in list(requirements.items())[:10]]

            if req_rows:
                embed.add_field(
                    name="Requirements",
                    value=self._shorten("\n".join(req_rows)),
                    inline=False,
                )

        identifications = item.get("identifications")
        if isinstance(identifications, dict):
            id_rows = []

            for key, value in list(identifications.items())[:12]:
                if isinstance(value, dict):
                    raw = value.get("raw", value.get("min", value.get("max", "")))
                    id_rows.append(f"{key}: {raw}")
                else:
                    id_rows.append(f"{key}: {value}")

            if id_rows:
                embed.add_field(
                    name="Identifications",
                    value=self._shorten("\n".join(id_rows)),
                    inline=False,
                )

        if len(results) > 1:
            others = [
                x.get("displayName") or x.get("internalName") or "?"
                for x in results[1:8]
                if isinstance(x, dict)
            ]

            if others:
                embed.set_footer(text="Other matches: " + ", ".join(others))

        await self._send_embed(ctx, embed)

    @staticmethod
    def _extract_item_candidates(data: Any) -> List[Dict[str, Any]]:
        if isinstance(data, list):
            return [x for x in data if isinstance(x, dict)]

        if not isinstance(data, dict):
            return []

        raw = data.get("results", data)

        if isinstance(raw, list):
            return [x for x in raw if isinstance(x, dict)]

        if isinstance(raw, dict):
            return [x for x in raw.values() if isinstance(x, dict)]

        return []

    @wynn.command(name="search")
    async def search(self, ctx: commands.Context, *, query: str):
        """Global Wynncraft search."""
        try:
            data = await self._request(
                f"/search/{quote(query, safe='')}",
                ttl=self.TTL_SEARCH,
            )
        except Exception as exc:
            return await self._send_error(ctx, exc)

        embed = self._embed(f"Wynncraft Search: {query}")

        if not isinstance(data, dict):
            embed.description = self._shorten(data)
            return await self._send_embed(ctx, embed)

        added = False

        for category, values in list(data.items())[:8]:
            if not values:
                continue

            if isinstance(values, dict):
                text = "\n".join(str(x) for x in list(values.keys())[:10])
            elif isinstance(values, list):
                text = "\n".join(self._result_label(x) for x in values[:10])
            else:
                text = str(values)

            embed.add_field(name=str(category), value=self._shorten(text), inline=False)
            added = True

        if not added:
            embed.description = "No results."

        await self._send_embed(ctx, embed)

    @wynn.command(name="lbtypes")
    async def leaderboard_types(self, ctx: commands.Context):
        """List leaderboard types."""
        try:
            data = await self._request("/leaderboards/types", ttl=self.TTL_LEADERBOARD)
        except Exception as exc:
            return await self._send_error(ctx, exc)

        if not isinstance(data, list):
            return await ctx.send("Unexpected leaderboard types response.")

        embed = self._embed("Wynncraft Leaderboard Types")
        embed.description = self._shorten(", ".join(str(x) for x in data[:80]), 4000) or "No types found."

        if len(data) > 80:
            embed.set_footer(text=f"Showing 80 of {len(data)} types.")

        await self._send_embed(ctx, embed)

    @wynn.command(name="lb", aliases=["leaderboard"])
    async def leaderboard(self, ctx: commands.Context, lb_type: str, limit: int = 10):
        """Show leaderboard by type."""
        limit = max(1, min(limit, 25))

        try:
            data = await self._request(
                f"/leaderboards/{quote(lb_type, safe='')}",
                ttl=self.TTL_LEADERBOARD,
            )
        except Exception as exc:
            return await self._send_error(ctx, exc)

        if isinstance(data, list):
            entries = data
        elif isinstance(data, dict):
            entries = data.get("results") or data.get("data") or list(data.items())
        else:
            entries = []

        rows = [
            f"`#{i}` {self._leaderboard_label(entry)}"
            for i, entry in enumerate(list(entries)[:limit], start=1)
        ]

        embed = self._embed(f"Leaderboard: {lb_type}", "\n".join(rows) or "No entries found.")
        await self._send_embed(ctx, embed)

    @wynn.command(name="markers")
    async def markers(self, ctx: commands.Context, *, query: Optional[str] = None):
        """List map markers or search by marker name."""
        try:
            data = await self._request("/map/locations/markers", ttl=self.TTL_MARKERS)
        except Exception as exc:
            return await self._send_error(ctx, exc)

        if not isinstance(data, list):
            return await ctx.send("Unexpected marker response.")

        rows = []
        needle = query.lower() if query else None

        for marker in data:
            if not isinstance(marker, dict):
                continue

            name = str(marker.get("name", "Unknown"))

            if needle and needle not in name.lower():
                continue

            rows.append(
                f"**{name}** — x:{marker.get('x', '?')} "
                f"y:{marker.get('y', '?')} z:{marker.get('z', '?')}"
            )

        title = "Wynncraft Map Markers" + (f": {query}" if query else "")
        embed = self._embed(title, "\n".join(rows[:25]) or "No markers found.")

        if len(rows) > 25:
            embed.set_footer(text=f"Showing 25 of {len(rows)} matching markers.")

        await self._send_embed(ctx, embed)

    @commands.group(name="wynnwatch", invoke_without_command=True)
    @commands.guild_only()
    async def wynnwatch(self, ctx: commands.Context):
        """Online watch alert commands."""
        p = ctx.clean_prefix

        await ctx.send(
            f"`{p}wynnwatch enable`\n"
            f"`{p}wynnwatch disable`\n"
            f"`{p}wynnwatch channel [#channel]`\n"
            f"`{p}wynnwatch add <username>`\n"
            f"`{p}wynnwatch remove <username>`\n"
            f"`{p}wynnwatch list`\n"
            f"`{p}wynnwatch interval <seconds>`\n"
            f"`{p}wynnwatch mode <alert|board>`\n"
            f"`{p}wynnwatch boardinit`\n"
            f"`{p}wynnwatch check`"
        )

    @wynnwatch.command(name="enable")
    @commands.guild_only()
    @checks.admin_or_permissions(manage_guild=True)
    async def watch_enable(self, ctx: commands.Context):
        """Enable online watch for this guild."""
        await self.config.guild(ctx.guild).watch_enabled.set(True)
        await ctx.send("✅ Wynncraft online watch enabled.")

    @wynnwatch.command(name="disable")
    @commands.guild_only()
    @checks.admin_or_permissions(manage_guild=True)
    async def watch_disable(self, ctx: commands.Context):
        """Disable online watch for this guild."""
        await self.config.guild(ctx.guild).watch_enabled.set(False)
        await ctx.send("✅ Wynncraft online watch disabled.")

    @wynnwatch.command(name="channel")
    @commands.guild_only()
    @checks.admin_or_permissions(manage_guild=True)
    async def watch_channel(
        self,
        ctx: commands.Context,
        channel: Optional[discord.TextChannel] = None,
    ):
        """Set alert channel."""
        channel = channel or ctx.channel

        if not isinstance(channel, discord.TextChannel):
            return await ctx.send("⚠️ Please select a valid text channel.")

        await self.config.guild(ctx.guild).watch_channel_id.set(channel.id)
        await ctx.send(f"✅ Wynncraft alerts will be sent to {channel.mention}")

    @wynnwatch.command(name="add")
    @commands.guild_only()
    @checks.admin_or_permissions(manage_guild=True)
    async def watch_add(self, ctx: commands.Context, username: str):
        """Add player to watch list."""
        username = username.strip()

        if not username:
            return await ctx.send("⚠️ Username cannot be empty.")

        if len(username) > 32:
            return await ctx.send("⚠️ Username is too long.")

        async with self.config.guild(ctx.guild).watch_players() as players:
            if username.lower() not in [p.lower() for p in players]:
                players.append(username)

        await ctx.send(f"✅ Added `{username}` to watch list.")

    @wynnwatch.command(name="remove")
    @commands.guild_only()
    @checks.admin_or_permissions(manage_guild=True)
    async def watch_remove(self, ctx: commands.Context, username: str):
        """Remove player from watch list."""
        username = username.strip()

        if not username:
            return await ctx.send("⚠️ Username cannot be empty.")

        async with self.config.guild(ctx.guild).watch_players() as players:
            players[:] = [p for p in players if p.lower() != username.lower()]

        await ctx.send(f"✅ Removed `{username}` from watch list.")

    @wynnwatch.command(name="interval")
    @commands.guild_only()
    @checks.admin_or_permissions(manage_guild=True)
    async def watch_interval(self, ctx: commands.Context, seconds: int):
        """Set watch interval. Recommended: 300 seconds for low usage."""
        seconds = max(60, min(seconds, 3600))

        await self.config.guild(ctx.guild).watch_interval.set(seconds)
        await ctx.send(f"✅ Watch interval set to `{seconds}` seconds.")

    @wynnwatch.command(name="mode")
    @commands.guild_only()
    @checks.admin_or_permissions(manage_guild=True)
    async def watch_mode(self, ctx: commands.Context, mode: str):
        """Set watch mode: alert sends messages, board edits one minimal embed."""
        mode = mode.strip().lower()

        if mode not in {"alert", "board"}:
            return await ctx.send("⚠️ Mode must be `alert` or `board`.")

        await self.config.guild(ctx.guild).watch_mode.set(mode)
        await ctx.send(f"✅ Wynncraft watch mode set to `{mode}`.")

    @wynnwatch.command(name="boardinit", aliases=["board", "initboard"])
    @commands.guild_only()
    @checks.admin_or_permissions(manage_guild=True)
    async def watch_board_init(self, ctx: commands.Context):
        """Create or refresh the Wynncraft Watch board message now."""
        await self.config.guild(ctx.guild).watch_mode.set("board")
        result = await self._run_watch_for_guild(ctx.guild, manual=True, force_board=True)
        await ctx.send(result)

    @wynnwatch.command(name="list")
    @commands.guild_only()
    async def watch_list(self, ctx: commands.Context):
        """Show watch settings."""
        settings = await self.config.guild(ctx.guild).all()
        channel_id = settings.get("watch_channel_id")
        channel = ctx.guild.get_channel(channel_id) if channel_id else None

        embed = self._embed("Wynncraft Watch Settings")
        embed.add_field(name="Enabled", value=self._fmt_bool(settings.get("watch_enabled")), inline=True)
        embed.add_field(
            name="Interval",
            value=f"{settings.get('watch_interval', 300)} seconds",
            inline=True,
        )
        embed.add_field(
            name="Mode",
            value=str(settings.get("watch_mode") or "alert"),
            inline=True,
        )
        embed.add_field(
            name="Channel",
            value=channel.mention if channel else "Not set",
            inline=False,
        )
        embed.add_field(
            name="Players",
            value=", ".join(settings.get("watch_players") or []) or "No players.",
            inline=False,
        )

        await self._send_embed(ctx, embed)

    @wynnwatch.command(name="check")
    @commands.guild_only()
    @checks.admin_or_permissions(manage_guild=True)
    async def watch_check(self, ctx: commands.Context):
        """Manually run one watch check for this guild."""
        result = await self._run_watch_for_guild(ctx.guild, manual=True)
        await ctx.send(result)

    async def _watch_loop(self):
        await self.bot.wait_until_ready()

        while True:
            try:
                await self._run_watch_for_all_guilds()
            except asyncio.CancelledError:
                raise
            except Exception:
                log.exception("Wynncraft watch loop failed.")

            sleep_seconds = await self.config.watch_loop_sleep_seconds()
            await asyncio.sleep(max(60, int(sleep_seconds or 60)))

    async def _run_watch_for_all_guilds(self):
        all_guilds = await self.config.all_guilds()
        enabled_guild_ids = []

        now = time.time()

        for guild_id, settings in all_guilds.items():
            if not settings.get("watch_enabled"):
                continue

            players = settings.get("watch_players") or []
            channel_id = settings.get("watch_channel_id")

            if not players or not channel_id:
                continue

            interval = int(settings.get("watch_interval") or 300)
            last_check = float(settings.get("last_watch_check_ts") or 0.0)

            if now - last_check < interval:
                continue

            enabled_guild_ids.append(guild_id)

        if not enabled_guild_ids:
            return

        online_names = await self._get_visible_online_names(use_cache=True)

        for guild_id in enabled_guild_ids:
            guild = self.bot.get_guild(guild_id)

            if not guild:
                continue

            try:
                await self._run_watch_for_guild(
                    guild,
                    visible_online_names=online_names,
                    manual=False,
                )
            except Exception:
                log.exception("Wynncraft watch check failed for guild_id=%s", guild_id)

    async def _run_watch_for_guild(
        self,
        guild: discord.Guild,
        *,
        visible_online_names: Optional[set[str]] = None,
        manual: bool = False,
        force_board: bool = False,
    ) -> str:
        settings = await self.config.guild(guild).all()

        if visible_online_names is None:
            visible_online_names = await self._get_visible_online_names(use_cache=not manual)

        channel_id = settings.get("watch_channel_id")
        players = settings.get("watch_players") or []
        channel = guild.get_channel(channel_id) if channel_id else None

        await self.config.guild(guild).last_watch_check_ts.set(time.time())

        if not players:
            return "⚠️ Watch list is empty."

        if not isinstance(channel, discord.TextChannel):
            return "⚠️ Watch channel is not set or no longer exists."

        me = guild.me
        if me is None and self.bot.user is not None:
            me = guild.get_member(self.bot.user.id)

        if me is None:
            return "⚠️ Unable to resolve bot member in this guild."

        permissions = channel.permissions_for(me)
        if not permissions.send_messages:
            return "⚠️ I do not have permission to send messages in the watch channel."

        watch_mode = str(settings.get("watch_mode") or "alert").lower()

        if watch_mode == "board" or force_board:
            return await self._update_watch_board(
                guild,
                channel,
                players,
                visible_online_names,
                interval=int(settings.get("watch_interval") or 300),
                use_cache=not manual,
            )

        last_state = settings.get("last_online_state") or {}
        new_state = dict(last_state)
        last_seen = settings.get("watch_last_seen") or {}
        new_last_seen = dict(last_seen) if isinstance(last_seen, dict) else {}
        now_ts = int(time.time())
        last_seen_changed = False
        sent_count = 0

        for username in players:
            key = username.lower()
            is_online = key in visible_online_names
            was_online = bool(last_state.get(key, False))
            new_state[key] = is_online
            if is_online:
                new_last_seen[key] = now_ts
                last_seen_changed = True

            try:
                if is_online and not was_online:
                    await channel.send(f"🟢 **{username}** is now online on Wynncraft.")
                    sent_count += 1
                elif was_online and not is_online:
                    await channel.send(f"⚪ **{username}** is no longer visible as online on Wynncraft.")
                    sent_count += 1
            except discord.HTTPException:
                log.exception(
                    "Failed to send Wynncraft watch alert. guild_id=%s channel_id=%s username=%s",
                    guild.id,
                    channel.id,
                    username,
                )

        await self.config.guild(guild).last_online_state.set(new_state)
        if last_seen_changed:
            await self.config.guild(guild).watch_last_seen.set(new_last_seen)

        if manual:
            online_watched = [p for p in players if p.lower() in visible_online_names]
            return (
                "✅ Manual check complete. Online watched players: "
                f"{', '.join(online_watched) if online_watched else 'None'}"
            )

        return f"Check complete. Sent {sent_count} alert(s)."

    async def _update_watch_board(
        self,
        guild: discord.Guild,
        channel: discord.TextChannel,
        players: List[str],
        visible_online_names: set[str],
        *,
        interval: int,
        use_cache: bool,
    ) -> str:
        embed = await self._build_watch_board_embed(
            guild,
            players,
            visible_online_names,
            interval=interval,
            use_cache=use_cache,
        )
        message_id = await self.config.guild(guild).watch_board_message_id()

        try:
            if message_id:
                message = channel.get_partial_message(int(message_id))
                await message.edit(embed=embed)
                return "✅ Wynncraft Watch board updated."

            message = await channel.send(embed=embed)
            await self.config.guild(guild).watch_board_message_id.set(message.id)
            return "✅ Wynncraft Watch board created."

        except discord.NotFound:
            message = await channel.send(embed=embed)
            await self.config.guild(guild).watch_board_message_id.set(message.id)
            return "✅ Wynncraft Watch board recreated."
        except discord.Forbidden:
            return "⚠️ I do not have permission to create or edit the watch board message."
        except discord.HTTPException:
            log.exception(
                "Failed to update Wynncraft watch board. guild_id=%s channel_id=%s",
                guild.id,
                channel.id,
            )
            return "⚠️ Failed to update the watch board message."

    async def _build_watch_board_embed(
        self,
        guild: discord.Guild,
        players: List[str],
        visible_online_names: set[str],
        *,
        interval: int,
        use_cache: bool,
    ) -> discord.Embed:
        online_rows: List[str] = []
        offline_rows: List[str] = []
        last_seen = await self.config.guild(guild).watch_last_seen()
        if not isinstance(last_seen, dict):
            last_seen = {}
        new_last_seen = dict(last_seen)
        now_ts = int(time.time())
        last_seen_changed = False

        for username in players:
            clean_name = username.strip()
            if not clean_name:
                continue

            key = clean_name.lower()

            if key in visible_online_names:
                new_last_seen[key] = now_ts
                last_seen_changed = True
                server = "N/A"
                highest_class = "N/A"

                try:
                    profile = await self._get_player_profile(clean_name, use_cache=use_cache)
                    if isinstance(profile, dict):
                        server = str(profile.get("server") or "N/A")

                    highest_class = await self._get_highest_character_label(
                        clean_name,
                        use_cache=use_cache,
                    )
                except Exception:
                    log.exception("Failed to load online watch details for username=%s", clean_name)

                online_rows.append(self._format_online_board_box(clean_name, server, highest_class))
            else:
                highest_class = "N/A"

                try:
                    highest_class = await self._get_highest_character_label(
                        clean_name,
                        use_cache=use_cache,
                    )
                except Exception:
                    log.exception("Failed to load offline watch class for username=%s", clean_name)

                last_active = self._format_last_seen(new_last_seen.get(key))
                offline_rows.append(self._format_offline_board_box(clean_name, highest_class, last_active))

        if last_seen_changed:
            await self.config.guild(guild).watch_last_seen.set(new_last_seen)

        embed = self._embed("Wynncraft Watch by YunYun")
        embed.add_field(
            name="🟢 Online",
            value=self._format_board_field(online_rows, "No online players."),
            inline=False,
        )
        embed.add_field(
            name="⚪ Offline",
            value=self._format_board_field(offline_rows, "No offline players."),
            inline=False,
        )
        embed.set_footer(text=f"Auto refresh every {interval}s")
        embed.timestamp = discord.utils.utcnow()
        return embed

    @staticmethod
    def _clean_board_text(value: Any, limit: int = 48) -> str:
        text = "N/A" if value is None else str(value)
        text = text.replace("\n", " ").replace("`", "'").strip()
        if len(text) > limit:
            text = text[: max(0, limit - 3)] + "..."
        return text

    @classmethod
    def _format_online_board_box(cls, name: str, server: str, highest_class: str) -> str:
        return "\n".join(
            [
                cls._clean_board_text(name),
                f"Server : {cls._clean_board_text(server or 'N/A')}",
                f"Class  : {cls._clean_board_text(highest_class or 'N/A')}",
            ]
        )

    @classmethod
    def _format_offline_board_box(cls, name: str, highest_class: str, last_active: str) -> str:
        return "\n".join(
            [
                cls._clean_board_text(name),
                f"Class  : {cls._clean_board_text(highest_class or 'N/A')}",
                f"Last Active: {cls._clean_board_text(last_active or 'Never', 64)}",
            ]
        )

    @staticmethod
    def _format_last_seen(value: Any) -> str:
        try:
            ts = int(float(value))
        except (TypeError, ValueError):
            return "Never"

        if ts <= 0:
            return "Never"

        return datetime.fromtimestamp(ts, tz=timezone.utc).strftime("%Y-%m-%d %H:%M UTC")

    def _format_board_field(self, rows: List[str], empty_text: str) -> str:
        text = "\n\n".join(rows) if rows else empty_text
        return f"```text\n{self._shorten(text, 1008)}\n```"

    async def _get_player_profile(self, username_or_uuid: str, *, use_cache: bool) -> Any:
        return await self._request(
            f"/player/{quote(username_or_uuid, safe='')}",
            ttl=self.TTL_PLAYER,
            use_cache=use_cache,
        )

    async def _get_highest_character_label(self, username_or_uuid: str, *, use_cache: bool) -> str:
        data = await self._request(
            f"/player/{quote(username_or_uuid, safe='')}/characters",
            ttl=self.TTL_PLAYER,
            use_cache=use_cache,
        )

        if not isinstance(data, dict) or not data:
            return "N/A"

        best_label = "N/A"
        best_level = -1

        for char in data.values():
            if not isinstance(char, dict):
                continue

            level = char.get("level")
            if not isinstance(level, int):
                try:
                    level = int(level)
                except (TypeError, ValueError):
                    level = -1

            if level > best_level:
                ctype = str(char.get("type") or "UNKNOWN")
                reskin = char.get("reskin")
                label = f"{ctype}/{reskin}" if reskin else ctype
                best_label = f"{label} Lv.{level}" if level >= 0 else label
                best_level = level

        return best_label

    async def _get_visible_online_names(self, *, use_cache: bool) -> set[str]:
        data = await self._request(
            "/player",
            params={"identifier": "username"},
            ttl=self.TTL_ONLINE,
            use_cache=use_cache,
        )

        if not isinstance(data, dict) or not isinstance(data.get("players"), dict):
            return set()

        return {name.lower() for name in data["players"].keys()}

    @staticmethod
    def _result_label(value: Any) -> str:
        if isinstance(value, dict):
            for key in ("displayName", "name", "username", "prefix", "internalName"):
                if value.get(key):
                    return str(value[key])

            return str(value)[:120]

        return str(value)

    @staticmethod
    def _leaderboard_label(entry: Any) -> str:
        if isinstance(entry, tuple) and len(entry) == 2:
            return f"{entry[0]} — {entry[1]}"

        if isinstance(entry, dict):
            name = (
                entry.get("name")
                or entry.get("username")
                or entry.get("player")
                or entry.get("guild")
                or entry.get("uuid")
                or "Unknown"
            )

            value = (
                entry.get("value")
                or entry.get("score")
                or entry.get("level")
                or entry.get("totalLevel")
                or entry.get("xp")
                or entry.get("rating")
                or ""
            )

            return f"**{name}** {value}".strip()

        return str(entry)