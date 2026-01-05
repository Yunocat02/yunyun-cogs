from __future__ import annotations

import asyncio
import base64
import logging
import re
import time
import urllib.parse
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple, Literal

import aiohttp
import discord
from redbot.core import commands, Config

log = logging.getLogger("red.vrchat")

VRCHAT_API_BASE = "https://api.vrchat.cloud/api/1"

USER_ID_RE = re.compile(r"^usr_[0-9a-fA-F-]{36}$")
WORLD_ID_RE = re.compile(r"^wrld_[0-9a-fA-F-]{36}$")


# -----------------------------
# Helpers
# -----------------------------
def _clip(text: Optional[str], limit: int) -> str:
    if not text:
        return "—"
    text = str(text).strip()
    if len(text) <= limit:
        return text
    return text[: max(0, limit - 1)] + "…"


def _iso_to_unix(iso_str: Optional[str]) -> Optional[int]:
    if not iso_str or iso_str in ("none", "null"):
        return None
    try:
        s = iso_str.replace("Z", "+00:00")
        dt = datetime.fromisoformat(s)
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return int(dt.timestamp())
    except Exception:
        return None


def _fmt_discord_time(iso_str: Optional[str]) -> str:
    ts = _iso_to_unix(iso_str)
    if not ts:
        return "—"
    return f"<t:{ts}:f>  •  <t:{ts}:R>"


def _status_emoji(state: Optional[str]) -> str:
    s = (state or "").lower()
    if s in ("online", "active"):
        return "🟢"
    if s in ("ask me", "askme"):
        return "🟡"
    if s in ("busy", "do not disturb"):
        return "🔴"
    if s in ("offline",):
        return "⚫"
    return "🔵"


def _user_profile_url(user_id: str) -> str:
    return f"https://vrchat.com/home/user/{user_id}"


def _world_profile_url(world_id: str) -> str:
    return f"https://vrchat.com/home/world/{world_id}"


def _world_launch_url(world_id: str, instance_id: Optional[str] = None) -> str:
    if instance_id:
        qi = urllib.parse.quote(instance_id, safe="~()=%,:_-")
        return f"https://vrchat.com/home/launch?instanceId={qi}&worldId={world_id}"
    return f"https://vrchat.com/home/launch?worldId={world_id}"


def _parse_location(location: Optional[str]) -> Tuple[Optional[str], Optional[str], str]:
    """
    VRChat 'location' can be:
      - "", "offline", "private", "traveling", "traveling:traveling"
      - or 'wrld_...:instanceId'
    Return: (world_id, instance_id, kind)
    kind: "world" | "offline" | "private" | "traveling" | "unknown"
    """
    if not location:
        return None, None, "unknown"
    loc = location.strip()
    low = loc.lower()

    if low == "offline":
        return None, None, "offline"
    if low.startswith("traveling"):
        return None, None, "traveling"
    if low == "private":
        return None, None, "private"

    if ":" in loc:
        world_part, inst_part = loc.split(":", 1)
        world_part = world_part.strip()
        inst_part = inst_part.strip()
        if WORLD_ID_RE.match(world_part):
            return world_part, (inst_part or None), "world"

    if WORLD_ID_RE.match(loc):
        return loc, None, "world"

    return None, None, "unknown"


# -----------------------------
# VRChat API
# -----------------------------
class VRChatError(Exception):
    def __init__(self, status: int, message: str):
        super().__init__(message)
        self.status = status
        self.message = message


class VRChatAPI:
    """
    Minimal VRChat API client.
    Uses saved auth cookie to avoid repeated login.
    """

    def __init__(self, config: Config, user_agent: str):
        self.config = config
        self.user_agent = user_agent
        self._session: Optional[aiohttp.ClientSession] = None
        self._login_lock = asyncio.Lock()

    async def close(self):
        if self._session and not self._session.closed:
            await self._session.close()

    async def _get_session(self) -> aiohttp.ClientSession:
        if self._session is None or self._session.closed:
            jar = aiohttp.CookieJar(unsafe=True)
            self._session = aiohttp.ClientSession(
                cookie_jar=jar,
                raise_for_status=False,
                timeout=aiohttp.ClientTimeout(total=25),
                headers={"User-Agent": self.user_agent, "Accept": "application/json"},
            )

            saved_auth = await self.config.auth_cookie()
            if saved_auth:
                jar.update_cookies({"auth": saved_auth}, response_url=VRCHAT_API_BASE)
        return self._session

    async def _save_auth_cookie(self):
        sess = await self._get_session()
        cookies = sess.cookie_jar.filter_cookies(VRCHAT_API_BASE)
        auth = cookies.get("auth")
        if auth and auth.value:
            await self.config.auth_cookie.set(auth.value)

    async def _read_json_or_text(self, resp: aiohttp.ClientResponse) -> Any:
        try:
            return await resp.json(content_type=None)
        except Exception:
            try:
                return await resp.text()
            except Exception:
                return None

    async def _has_valid_cookie(self) -> bool:
        try:
            await self.request("GET", "/auth/user", auth_mode="cookie_only")
            return True
        except VRChatError:
            return False

    async def login_if_needed(self):
        async with self._login_lock:
            if await self._has_valid_cookie():
                return

            username = await self.config.vrchat_username()
            password = await self.config.vrchat_password()
            if not username or not password:
                raise VRChatError(
                    401,
                    "VRChat credentials not set. Owner must run: `vrc.setcreds <username> <password>`",
                )

            u = urllib.parse.quote(username, safe="")
            p = urllib.parse.quote(password, safe="")
            token = base64.b64encode(f"{u}:{p}".encode("utf-8")).decode("utf-8")

            sess = await self._get_session()
            url = f"{VRCHAT_API_BASE}/auth/user"

            async with sess.get(url, headers={"Authorization": f"Basic {token}"}) as resp:
                data = await self._read_json_or_text(resp)
                if resp.status != 200:
                    msg = None
                    if isinstance(data, dict):
                        msg = (data.get("error") or {}).get("message") or data.get("message")
                    elif isinstance(data, str):
                        msg = data.strip()
                    raise VRChatError(resp.status, msg or "Login failed (maybe 2FA required).")

                await self._save_auth_cookie()

    async def request(
        self,
        method: str,
        path: str,
        *,
        params: Optional[Dict[str, Any]] = None,
        auth_mode: Literal["auto", "cookie_only", "none"] = "auto",
        allow_unauth: bool = False,
    ) -> Any:
        sess = await self._get_session()
        url = f"{VRCHAT_API_BASE}{path}"

        if auth_mode == "auto":
            try:
                await self.login_if_needed()
            except VRChatError:
                if not allow_unauth:
                    raise

        async with sess.request(method, url, params=params) as resp:
            data = await self._read_json_or_text(resp)

            if resp.status == 204:
                return None

            if resp.status >= 400:
                msg = None
                if isinstance(data, dict):
                    msg = (data.get("error") or {}).get("message") or data.get("message")
                elif isinstance(data, str):
                    msg = data.strip()
                raise VRChatError(resp.status, _clip(msg or f"HTTP {resp.status}", 400))

            return data

    # ---- endpoints ----
    async def get_user_by_id(self, user_id: str) -> Dict[str, Any]:
        data = await self.request("GET", f"/users/{user_id}")
        return data if isinstance(data, dict) else {}

    async def search_users(self, search: str, n: int = 60, offset: int = 0) -> List[Dict[str, Any]]:
        data = await self.request("GET", "/users", params={"search": search, "n": n, "offset": offset})
        return data if isinstance(data, list) else []

    async def get_world_by_id(self, world_id: str) -> Dict[str, Any]:
        data = await self.request("GET", f"/worlds/{world_id}", allow_unauth=True)
        return data if isinstance(data, dict) else {}

    async def search_worlds(self, search: str, n: int = 60, offset: int = 0, sort: str = "popularity") -> List[Dict[str, Any]]:
        data = await self.request("GET", "/worlds", params={"search": search, "n": n, "offset": offset, "sort": sort})
        return data if isinstance(data, list) else []


# -----------------------------
# Detail Actions View (for direct uid/wid)
# - Pin Detail
# - Show Author Profile (world only)
# -----------------------------
class DetailActionsView(discord.ui.View):
    def __init__(
        self,
        cog: "VRChatCog",
        author_id: int,
        kind: Literal["user", "world"],
        embed: discord.Embed,
        payload: Dict[str, Any],
        timeout: int = 240,
    ):
        super().__init__(timeout=timeout)
        self.cog = cog
        self.author_id = author_id
        self.kind = kind
        self.current_embed = embed
        self.current_payload = payload

        self._sync()

    async def interaction_check(self, interaction: discord.Interaction) -> bool:
        if interaction.user and interaction.user.id == self.author_id:
            return True
        await interaction.response.send_message("ปุ่มนี้ใช้ได้เฉพาะคนที่สั่งคำสั่งเท่านั้นครับ", ephemeral=True)
        return False

    def _sync(self):
        self.pin_button.disabled = (self.current_embed is None)
        if self.kind == "world":
            aid = str(self.current_payload.get("authorId") or "").strip()
            self.author_button.disabled = not USER_ID_RE.match(aid)
        else:
            self.author_button.disabled = True

    @discord.ui.button(label="📌 Pin Detail", style=discord.ButtonStyle.success)
    async def pin_button(self, interaction: discord.Interaction, button: discord.ui.Button):
        self._sync()
        await interaction.response.send_message("✅ ส่งรายละเอียดเป็นข้อความใหม่แล้ว", ephemeral=True)
        if interaction.channel:
            await interaction.channel.send(embed=self.current_embed)

    @discord.ui.button(label="👤 Show Author Profile", style=discord.ButtonStyle.primary)
    async def author_button(self, interaction: discord.Interaction, button: discord.ui.Button):
        self._sync()
        if self.kind != "world":
            return await interaction.response.send_message("ปุ่มนี้ใช้ได้เฉพาะหน้า World detail ครับ", ephemeral=True)

        author_id = str(self.current_payload.get("authorId") or "").strip()
        if not USER_ID_RE.match(author_id):
            return await interaction.response.send_message("หา authorId ไม่เจอ/รูปแบบไม่ถูกต้องครับ", ephemeral=True)

        try:
            u = await self.cog.api.get_user_by_id(author_id)
            embed = await self.cog._build_user_detail_embed(u, title_prefix="👤 Author")
        except VRChatError as e:
            return await interaction.response.send_message(f"ดึง Author ไม่สำเร็จ (HTTP {e.status}): {_clip(e.message, 200)}", ephemeral=True)

        await interaction.response.send_message("✅ ส่งโปรไฟล์ Author เป็นข้อความใหม่แล้ว", ephemeral=True)
        if interaction.channel:
            await interaction.channel.send(embed=embed, view=DetailActionsView(self.cog, self.author_id, "user", embed, u))

    @discord.ui.button(label="Close", style=discord.ButtonStyle.danger)
    async def close_button(self, interaction: discord.Interaction, button: discord.ui.Button):
        for child in self.children:
            if isinstance(child, (discord.ui.Button, discord.ui.Select)):
                child.disabled = True
        await interaction.response.edit_message(view=self)
        self.stop()


# -----------------------------
# Search UI View (Pagination + Select + Detail Mode)
# - Pin Detail
# - Show Author Profile (world detail only)
# -----------------------------
class SearchResultsView(discord.ui.View):
    def __init__(
        self,
        cog: "VRChatCog",
        author_id: int,
        kind: Literal["user", "world"],
        items: List[Dict[str, Any]],
        per_page: int = 10,
        timeout: int = 240,
    ):
        super().__init__(timeout=timeout)
        self.cog = cog
        self.author_id = author_id
        self.kind = kind
        self.items = items
        self.per_page = per_page

        self.page = 0
        self.mode: Literal["list", "detail"] = "list"
        self._last_list_page = 0

        # current detail cache for Pin / Author
        self.current_detail_payload: Optional[Dict[str, Any]] = None
        self.current_detail_embed: Optional[discord.Embed] = None

        self.select_menu = discord.ui.Select(
            placeholder="เลือกเพื่อดูรายละเอียด…",
            min_values=1,
            max_values=1,
            options=[],
            row=0,
        )
        self.select_menu.callback = self._on_select
        self.add_item(self.select_menu)

        self._sync_buttons_and_select()

    def _max_page(self) -> int:
        return max(0, (len(self.items) - 1) // self.per_page)

    def _page_slice(self) -> List[Dict[str, Any]]:
        start = self.page * self.per_page
        return self.items[start : start + self.per_page]

    async def interaction_check(self, interaction: discord.Interaction) -> bool:
        if interaction.user and interaction.user.id == self.author_id:
            return True
        await interaction.response.send_message("ปุ่ม/เมนูนี้ใช้ได้เฉพาะคนที่สั่งคำสั่งเท่านั้นครับ", ephemeral=True)
        return False

    def _sync_buttons_and_select(self):
        self.prev_button.disabled = (self.mode != "list") or (self.page <= 0)
        self.next_button.disabled = (self.mode != "list") or (self.page >= self._max_page())
        self.back_button.disabled = (self.mode != "detail")
        self.pin_button.disabled = (self.mode != "detail") or (self.current_detail_embed is None)

        # author button only in world-detail mode and authorId exists
        if self.mode != "detail" or self.kind != "world" or not self.current_detail_payload:
            self.author_button.disabled = True
        else:
            aid = str(self.current_detail_payload.get("authorId") or "").strip()
            self.author_button.disabled = not USER_ID_RE.match(aid)

        if self.mode != "list":
            self.select_menu.disabled = True
            self.select_menu.options = [discord.SelectOption(label="(กด Back เพื่อกลับไปเลือก)", value="noop")]
            return

        self.select_menu.disabled = False
        opts: List[discord.SelectOption] = []
        chunk = self._page_slice()
        start_idx = self.page * self.per_page

        for i, it in enumerate(chunk, start=start_idx + 1):
            if self.kind == "user":
                label = (it.get("displayName") or "Unknown")[:90]
                uid = it.get("id") or "—"
                state = it.get("state") or it.get("status") or ""
                desc = f"{_status_emoji(state)} {state} • {uid}"[:100]
                opts.append(discord.SelectOption(label=f"{i}. {label}"[:100], value=str(uid), description=desc))
            else:
                label = (it.get("name") or "Unknown World")[:90]
                wid = it.get("id") or "—"
                occ = it.get("occupants")
                cap = it.get("capacity")
                rel = it.get("releaseStatus") or ""
                desc = f"👥 {occ}/{cap} • {rel} • {wid}"[:100]
                opts.append(discord.SelectOption(label=f"{i}. {label}"[:100], value=str(wid), description=desc))

        self.select_menu.options = opts

    def render_list_embed(self) -> discord.Embed:
        if self.kind == "user":
            return self.cog._render_user_search_page(self.items, self.page, self.per_page)
        return self.cog._render_world_search_page(self.items, self.page, self.per_page)

    async def render_detail(self, item_id: str) -> Tuple[discord.Embed, Dict[str, Any]]:
        if self.kind == "user":
            u = await self.cog.api.get_user_by_id(item_id)
            return await self.cog._build_user_detail_embed(u), u
        w = await self.cog.api.get_world_by_id(item_id)
        return self.cog._build_world_detail_embed(w), w

    async def _edit(self, interaction: discord.Interaction, embed: discord.Embed):
        self._sync_buttons_and_select()
        await interaction.response.edit_message(embed=embed, view=self)

    async def _on_select(self, interaction: discord.Interaction):
        if self.mode != "list":
            return await interaction.response.send_message("กด Back ไปหน้ารายการก่อนครับ", ephemeral=True)

        item_id = str(self.select_menu.values[0]).strip()
        self.mode = "detail"
        self._last_list_page = self.page

        try:
            embed, payload = await self.render_detail(item_id)
        except VRChatError as e:
            self.mode = "list"
            self.page = self._last_list_page
            self.current_detail_embed = None
            self.current_detail_payload = None
            self._sync_buttons_and_select()
            return await interaction.response.send_message(
                f"ดึงรายละเอียดไม่สำเร็จ (HTTP {e.status}): {_clip(e.message, 300)}",
                ephemeral=True,
            )

        self.current_detail_embed = embed
        self.current_detail_payload = payload
        await self._edit(interaction, embed)

    @discord.ui.button(label="◀ Prev", style=discord.ButtonStyle.secondary, row=1)
    async def prev_button(self, interaction: discord.Interaction, button: discord.ui.Button):
        self.page = max(0, self.page - 1)
        await self._edit(interaction, self.render_list_embed())

    @discord.ui.button(label="Next ▶", style=discord.ButtonStyle.secondary, row=1)
    async def next_button(self, interaction: discord.Interaction, button: discord.ui.Button):
        self.page = min(self._max_page(), self.page + 1)
        await self._edit(interaction, self.render_list_embed())

    @discord.ui.button(label="Back", style=discord.ButtonStyle.primary, row=1)
    async def back_button(self, interaction: discord.Interaction, button: discord.ui.Button):
        self.mode = "list"
        self.page = self._last_list_page
        self.current_detail_embed = None
        self.current_detail_payload = None
        await self._edit(interaction, self.render_list_embed())

    @discord.ui.button(label="📌 Pin Detail", style=discord.ButtonStyle.success, row=2)
    async def pin_button(self, interaction: discord.Interaction, button: discord.ui.Button):
        if not self.current_detail_embed:
            return await interaction.response.send_message("ยังไม่มีรายละเอียดให้ปักหมุดครับ", ephemeral=True)
        await interaction.response.send_message("✅ ส่งรายละเอียดเป็นข้อความใหม่แล้ว", ephemeral=True)
        if interaction.channel:
            await interaction.channel.send(embed=self.current_detail_embed)

    @discord.ui.button(label="👤 Show Author Profile", style=discord.ButtonStyle.primary, row=2)
    async def author_button(self, interaction: discord.Interaction, button: discord.ui.Button):
        if self.kind != "world" or not self.current_detail_payload:
            return await interaction.response.send_message("ปุ่มนี้ใช้ได้เฉพาะหน้า World detail ครับ", ephemeral=True)

        author_id = str(self.current_detail_payload.get("authorId") or "").strip()
        if not USER_ID_RE.match(author_id):
            return await interaction.response.send_message("หา authorId ไม่เจอ/รูปแบบไม่ถูกต้องครับ", ephemeral=True)

        try:
            u = await self.cog.api.get_user_by_id(author_id)
            embed = await self.cog._build_user_detail_embed(u, title_prefix="👤 Author")
        except VRChatError as e:
            return await interaction.response.send_message(f"ดึง Author ไม่สำเร็จ (HTTP {e.status}): {_clip(e.message, 200)}", ephemeral=True)

        await interaction.response.send_message("✅ ส่งโปรไฟล์ Author เป็นข้อความใหม่แล้ว", ephemeral=True)
        if interaction.channel:
            await interaction.channel.send(embed=embed, view=DetailActionsView(self.cog, self.author_id, "user", embed, u))

    @discord.ui.button(label="Close", style=discord.ButtonStyle.danger, row=2)
    async def close_button(self, interaction: discord.Interaction, button: discord.ui.Button):
        for child in self.children:
            if isinstance(child, (discord.ui.Button, discord.ui.Select)):
                child.disabled = True
        await interaction.response.edit_message(view=self)
        self.stop()


# -----------------------------
# Modal: Link VRChat ID
# -----------------------------
class LinkVRChatModal(discord.ui.Modal, title="Link VRChat Account"):
    vrchat_user_id = discord.ui.TextInput(
        label="VRChat User ID",
        placeholder="usr_xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx",
        required=True,
        max_length=64,
    )

    def __init__(self, cog: "VRChatCog"):
        super().__init__()
        self.cog = cog

    async def on_submit(self, interaction: discord.Interaction):
        user_id = str(self.vrchat_user_id.value).strip()
        if not USER_ID_RE.match(user_id):
            await interaction.response.send_message("รูปแบบไม่ถูกต้องครับ ต้องเป็น `usr_...` (UUID)", ephemeral=True)
            return

        try:
            profile = await self.cog.api.get_user_by_id(user_id)
        except VRChatError as e:
            await interaction.response.send_message(f"ดึงข้อมูลไม่สำเร็จ (HTTP {e.status}): {_clip(e.message, 300)}", ephemeral=True)
            return

        await self.cog.config.user(interaction.user).vrchat_user_id.set(user_id)
        embed = await self.cog._build_user_detail_embed(profile, title_prefix="✅ Linked")
        await interaction.response.send_message(embed=embed, ephemeral=True)


# -----------------------------
# Cog
# -----------------------------
class VRChatCog(commands.Cog):
    def __init__(self, bot):
        self.bot = bot
        self.config = Config.get_conf(self, identifier=2026010501, force_registration=True)

        self.config.register_global(
            vrchat_username=None,
            vrchat_password=None,
            auth_cookie=None,
            watch_interval_sec=60,
        )
        self.config.register_user(
            vrchat_user_id=None,
        )
        self.config.register_guild(
            watch_channel_id=None,
            watch_user_ids=[],
            watch_last={},  # user_id -> {state,status,location,displayName,lastSeen}
        )

        ua = f"Red-VRChatCog/3.0 (discord.py; bot_id={getattr(getattr(bot,'user',None),'id','unknown')})"
        self.api = VRChatAPI(self.config, user_agent=ua)

        self._world_cache: Dict[str, Tuple[Dict[str, Any], float]] = {}
        self._world_cache_ttl_sec = 600  # 10 min

        self._watch_task: Optional[asyncio.Task] = self.bot.loop.create_task(self._watch_loop())

    def cog_unload(self):
        if self._watch_task and not self._watch_task.done():
            self._watch_task.cancel()
        self.bot.loop.create_task(self.api.close())

    # -----------------------------
    # World cache
    # -----------------------------
    async def _get_world_cached(self, world_id: str) -> Optional[Dict[str, Any]]:
        now = time.time()
        cached = self._world_cache.get(world_id)
        if cached and cached[1] > now:
            return cached[0]

        try:
            w = await self.api.get_world_by_id(world_id)
        except VRChatError:
            return None

        if w:
            self._world_cache[world_id] = (w, now + self._world_cache_ttl_sec)
        return w

    # -----------------------------
    # Watchlist background loop
    # -----------------------------
    async def _wait_ready(self):
        try:
            await self.bot.wait_until_red_ready()
        except Exception:
            await self.bot.wait_until_ready()

    async def _watch_loop(self):
        await self._wait_ready()
        while True:
            try:
                interval = await self.config.watch_interval_sec()
                interval = int(interval) if interval else 60
                if interval < 20:
                    interval = 20

                await self._watch_tick()
                await asyncio.sleep(interval)

            except asyncio.CancelledError:
                break
            except Exception as e:
                log.exception("Watch loop error: %s", e)
                await asyncio.sleep(30)

    async def _watch_tick(self):
        # iterate guilds
        for guild in list(self.bot.guilds):
            try:
                gconf = self.config.guild(guild)
                ch_id = await gconf.watch_channel_id()
                if not ch_id:
                    continue
                channel = guild.get_channel(int(ch_id))
                if channel is None:
                    continue

                watch_ids: List[str] = await gconf.watch_user_ids()
                if not watch_ids:
                    continue

                last: Dict[str, Any] = await gconf.watch_last()
                if not isinstance(last, dict):
                    last = {}

                changed_any = False

                for uid in watch_ids:
                    uid = str(uid).strip()
                    if not USER_ID_RE.match(uid):
                        continue

                    try:
                        u = await self.api.get_user_by_id(uid)
                    except VRChatError:
                        # ไม่ลบออกอัตโนมัติ เผื่อแค่ชั่วคราว
                        await asyncio.sleep(0.6)
                        continue

                    new_state = str(u.get("state") or "")
                    new_status = str(u.get("status") or "")
                    new_location = str(u.get("location") or "")
                    display = str(u.get("displayName") or uid)

                    old = last.get(uid)
                    new_pack = {
                        "displayName": display,
                        "state": new_state,
                        "status": new_status,
                        "location": new_location,
                        "lastSeen": u.get("last_login"),
                    }

                    if isinstance(old, dict):
                        if (
                            old.get("state") != new_state
                            or old.get("status") != new_status
                            or old.get("location") != new_location
                        ):
                            embed = await self._build_watch_change_embed(uid, old, new_pack, u)
                            try:
                                await channel.send(embed=embed)
                            except Exception:
                                pass

                    last[uid] = new_pack
                    changed_any = True
                    await asyncio.sleep(0.8)  # กันยิงถี่เกิน

                if changed_any:
                    await gconf.watch_last.set(last)

            except Exception:
                continue

    async def _build_watch_change_embed(
        self,
        user_id: str,
        old: Dict[str, Any],
        new: Dict[str, Any],
        full_profile: Dict[str, Any],
    ) -> discord.Embed:
        name = new.get("displayName") or user_id

        old_loc = str(old.get("location") or "")
        new_loc = str(new.get("location") or "")

        old_wid, old_inst, old_kind = _parse_location(old_loc)
        new_wid, new_inst, new_kind = _parse_location(new_loc)

        em = discord.Embed(
            title=f"🔔 VRChat status changed • {name}",
            url=_user_profile_url(user_id),
            color=discord.Color.orange(),
        )

        thumb = (
            full_profile.get("currentAvatarThumbnailImageUrl")
            or full_profile.get("userIcon")
            or full_profile.get("profilePicOverrideThumbnail")
            or full_profile.get("profilePicOverride")
        )
        if thumb:
            em.set_thumbnail(url=thumb)

        em.add_field(
            name="Old",
            value=_clip(
                f"{_status_emoji(str(old.get('state') or ''))} state: `{old.get('state','—')}`\n"
                f"status: `{old.get('status','—')}`\n"
                f"location: `{_clip(old_loc, 180)}`",
                900,
            ),
            inline=True,
        )
        em.add_field(
            name="New",
            value=_clip(
                f"{_status_emoji(str(new.get('state') or ''))} state: `{new.get('state','—')}`\n"
                f"status: `{new.get('status','—')}`\n"
                f"location: `{_clip(new_loc, 180)}`",
                900,
            ),
            inline=True,
        )

        # enrich world if new has world
        if new_wid:
            w = await self._get_world_cached(new_wid)
            if w:
                w_name = w.get("name") or "Unknown World"
                em.add_field(
                    name="World (auto)",
                    value=_clip(
                        f"🌍 **{w_name}**\n"
                        f"`{new_wid}`\n"
                        f"[Open World]({_world_profile_url(new_wid)}) • [Launch]({_world_launch_url(new_wid, new_inst)})",
                        900,
                    ),
                    inline=False,
                )
            else:
                em.add_field(
                    name="World (auto)",
                    value=_clip(
                        f"`{new_wid}`\n"
                        f"[Open World]({_world_profile_url(new_wid)}) • [Launch]({_world_launch_url(new_wid, new_inst)})",
                        900,
                    ),
                    inline=False,
                )

        em.set_footer(text="Watchlist notification")
        em.timestamp = datetime.now(timezone.utc)
        return em

    # -----------------------------
    # Owner commands
    # -----------------------------
    @commands.command(name="vrc.setcreds")
    @commands.is_owner()
    async def vrc_setcreds(self, ctx: commands.Context, username: str, password: str):
        await self.config.vrchat_username.set(username)
        await self.config.vrchat_password.set(password)
        await self.config.auth_cookie.clear()
        await ctx.send("✅ ตั้งค่า VRChat credentials แล้ว (ล้าง cookie เดิมแล้ว)")

    @commands.command(name="vrc.clearcookie")
    @commands.is_owner()
    async def vrc_clearcookie(self, ctx: commands.Context):
        await self.config.auth_cookie.clear()
        await ctx.send("✅ ล้าง auth cookie แล้ว")

    @commands.command(name="vrc.watchinterval")
    @commands.is_owner()
    async def vrc_watchinterval(self, ctx: commands.Context, seconds: int):
        if seconds < 20:
            seconds = 20
        await self.config.watch_interval_sec.set(int(seconds))
        await ctx.send(f"✅ ตั้งค่า watch interval = {seconds}s")

    # -----------------------------
    # Embeds (pretty)
    # -----------------------------
    async def _build_user_detail_embed(self, u: Dict[str, Any], title_prefix: str = "", title: Optional[str] = None) -> discord.Embed:
        display = u.get("displayName") or "Unknown"
        uid = u.get("id") or "—"

        status = u.get("status")
        state = u.get("state")
        status_desc = u.get("statusDescription")

        pronouns = u.get("pronouns")
        bio = u.get("bio")
        bio_links = u.get("bioLinks") or []

        last_login = u.get("last_login")
        last_platform = u.get("last_platform")

        location = u.get("location")
        world_id = u.get("worldId")
        instance_id = u.get("instanceId")

        thumb = (
            u.get("currentAvatarThumbnailImageUrl")
            or u.get("userIcon")
            or u.get("profilePicOverrideThumbnail")
            or u.get("profilePicOverride")
        )

        t = title or f"{display}"
        if title_prefix:
            t = f"{title_prefix} • {t}"

        em = discord.Embed(
            title=t,
            url=_user_profile_url(uid) if uid != "—" else None,
            description=_clip(status_desc, 240),
            color=discord.Color.blurple(),
        )
        if thumb:
            em.set_thumbnail(url=thumb)

        em.add_field(name="🆔 User ID", value=f"`{uid}`", inline=False)

        st_line = f"{_status_emoji(state)} **State:** `{state or '—'}`\n"
        st_line += f"🏷️ **Status:** `{status or '—'}`\n"
        st_line += f"🧍 **Pronouns:** `{pronouns or '—'}`"
        em.add_field(name="Status", value=st_line, inline=True)

        act = f"🕒 **Last login:** {_fmt_discord_time(last_login)}\n"
        act += f"🖥️ **Last platform:** `{last_platform or '—'}`"
        em.add_field(name="Activity", value=act, inline=True)

        parsed_world_id, parsed_instance_id, kind = _parse_location(location)
        effective_world_id = world_id if WORLD_ID_RE.match(str(world_id or "")) else parsed_world_id
        effective_instance_id = instance_id or parsed_instance_id

        where_lines = []
        where_lines.append(f"📍 **Location:** `{_clip(location, 140)}`")
        where_lines.append(f"🔒 **Visibility:** `{kind}`" if kind in ("offline", "private", "traveling") else "🔒 **Visibility:** `world`")

        if effective_world_id:
            w = await self._get_world_cached(effective_world_id)
            if w:
                w_name = w.get("name") or "Unknown World"
                w_release = w.get("releaseStatus") or "—"
                w_occ = w.get("occupants")
                w_cap = w.get("capacity")

                where_lines.append(f"🌍 **World:** **{_clip(w_name, 70)}** (`{effective_world_id}`)")
                where_lines.append(f"👥 **Occupants/Cap:** `{w_occ}`/`{w_cap}` • `{w_release}`")
                where_lines.append(
                    "🔗 "
                    + " • ".join(
                        [
                            f"[Open World]({_world_profile_url(effective_world_id)})",
                            f"[Launch]({_world_launch_url(effective_world_id, effective_instance_id)})",
                        ]
                    )
                )
            else:
                where_lines.append(f"🌍 **World:** `{effective_world_id}`")
                where_lines.append(f"🚀 **Launch:** {_world_launch_url(effective_world_id, effective_instance_id)}")
        else:
            where_lines.append("🌍 **World:** —")

        if effective_instance_id:
            where_lines.append(f"🎟️ **Instance:** `{_clip(effective_instance_id, 140)}`")

        em.add_field(name="Where (auto)", value=_clip("\n".join(where_lines), 1000), inline=False)

        em.add_field(name="📝 Bio", value=_clip(bio, 900), inline=False)

        if bio_links:
            links = [str(x) for x in bio_links[:10] if x]
            em.add_field(name="🔗 Bio Links", value=_clip("\n".join(links), 900), inline=False)

        em.set_footer(text="Tip: มีปุ่ม Pin Detail เพื่อส่ง embed นี้เป็นข้อความใหม่ได้")
        return em

    def _build_world_detail_embed(self, w: Dict[str, Any], title_prefix: str = "", title: Optional[str] = None) -> discord.Embed:
        name = w.get("name") or "Unknown World"
        wid = w.get("id") or "—"
        author = w.get("authorName") or "—"
        author_id = w.get("authorId") or "—"
        desc = w.get("description")

        cap = w.get("capacity")
        rec_cap = w.get("recommendedCapacity")
        occupants = w.get("occupants")
        public_occ = w.get("publicOccupants")
        private_occ = w.get("privateOccupants")

        favorites = w.get("favorites")
        visits = w.get("visits")
        heat = w.get("heat")
        pop = w.get("popularity")
        release = w.get("releaseStatus")

        created = w.get("created_at")
        updated = w.get("updated_at")
        tags = w.get("tags") or []
        yt = w.get("previewYoutubeId")

        image = w.get("thumbnailImageUrl") or w.get("imageUrl")

        t = title or name
        if title_prefix:
            t = f"{title_prefix} • {t}"

        em = discord.Embed(
            title=t,
            url=_world_profile_url(wid) if wid != "—" else None,
            description=_clip(desc, 320),
            color=discord.Color.green(),
        )
        if image:
            em.set_thumbnail(url=image)

        em.add_field(name="🆔 World ID", value=f"`{wid}`", inline=False)
        em.add_field(name="👤 Author", value=f"{author}\n`{author_id}`", inline=True)

        caps = f"👥 **Capacity:** `{cap if cap is not None else '—'}`\n"
        caps += f"⭐ **Recommended:** `{rec_cap if rec_cap is not None else '—'}`\n"
        caps += f"🧑‍🤝‍🧑 **Occupants:** `{occupants if occupants is not None else '—'}` (public {public_occ}, private {private_occ})"
        em.add_field(name="Capacity", value=caps, inline=True)

        stats = f"❤️ **Favorites:** `{favorites if favorites is not None else '—'}`\n"
        stats += f"👣 **Visits:** `{visits if visits is not None else '—'}`\n"
        stats += f"🔥 **Heat:** `{heat if heat is not None else '—'}`\n"
        stats += f"📈 **Popularity:** `{pop if pop is not None else '—'}`"
        em.add_field(name="Stats", value=stats, inline=True)

        em.add_field(name="🔓 Release", value=f"`{release or '—'}`", inline=True)
        em.add_field(name="🗓️ Created", value=_fmt_discord_time(created), inline=True)
        em.add_field(name="🛠️ Updated", value=_fmt_discord_time(updated), inline=True)

        if tags:
            em.add_field(name="🏷️ Tags", value=_clip(", ".join(tags[:40]), 900), inline=False)
        if yt:
            em.add_field(name="▶ YouTube Preview", value=f"`{yt}`", inline=False)

        if wid and wid != "—":
            em.add_field(name="🚀 Quick Launch", value=f"[Launch World]({_world_launch_url(wid)})", inline=False)

        em.set_footer(text="Tip: ในหน้า World detail มีปุ่ม Show Author Profile")
        return em

    # -----------------------------
    # List page embeds
    # -----------------------------
    def _render_user_search_page(self, items: List[Dict[str, Any]], page: int, per_page: int) -> discord.Embed:
        start = page * per_page
        chunk = items[start : start + per_page]
        total = len(items)

        lines = []
        for i, u in enumerate(chunk, start=start + 1):
            dn = u.get("displayName") or "—"
            uid = u.get("id") or "—"
            state = u.get("state") or u.get("status") or ""
            pron = u.get("pronouns") or ""
            lines.append(f"**{i}.** {dn} {_status_emoji(state)} `{state}` {f'• `{pron}`' if pron else ''}\n`{uid}`")

        em = discord.Embed(
            title="👥 VRChat Users (results)",
            description="\n\n".join(lines) if lines else "ไม่พบผลลัพธ์",
            color=discord.Color.blurple(),
        )
        em.set_footer(text=f"Page {page+1}/{max(1, (total-1)//per_page + 1)} • เลือกจาก Dropdown เพื่อดูรายละเอียดทันที")
        return em

    def _render_world_search_page(self, items: List[Dict[str, Any]], page: int, per_page: int) -> discord.Embed:
        start = page * per_page
        chunk = items[start : start + per_page]
        total = len(items)

        lines = []
        for i, w in enumerate(chunk, start=start + 1):
            name = w.get("name") or "—"
            wid = w.get("id") or "—"
            occ = w.get("occupants")
            cap = w.get("capacity")
            release = w.get("releaseStatus") or ""
            lines.append(f"**{i}.** {name} • 👥 `{occ}`/`{cap}` • `{release}`\n`{wid}`")

        em = discord.Embed(
            title="🌍 VRChat Worlds (results)",
            description="\n\n".join(lines) if lines else "ไม่พบผลลัพธ์",
            color=discord.Color.green(),
        )
        em.set_footer(text=f"Page {page+1}/{max(1, (total-1)//per_page + 1)} • เลือกจาก Dropdown เพื่อดูรายละเอียดทันที")
        return em

    # -----------------------------
    # Commands
    # -----------------------------
    @commands.command(name="vrc.help")
    async def vrc_help(self, ctx: commands.Context):
        em = discord.Embed(title="VRChat Commands", color=discord.Color.blurple())
        em.description = (
            "• `vrc.help`\n"
            "• `vrc.uid <usr_...>` — user by ID (มีปุ่ม Pin)\n"
            "• `vrc.user <display name>` — search users + dropdown details (มี Pin)\n"
            "• `vrc.wid <wrld_...>` — world by ID (มี Pin + Show Author)\n"
            "• `vrc.world <world name>` — search worlds + dropdown details (มี Pin + Show Author)\n"
            "• `vrc.link` — link Discord ↔ VRChat ID (modal)\n"
            "• `vrc.me` — show your linked profile\n"
            "• `vrc.profile @member` — show member linked profile\n\n"
            "**Watchlist (guild)**\n"
            "• `vrc.watchchannel [#channel]` — ตั้งห้องแจ้งเตือน\n"
            "• `vrc.watch [usr_... | @member]` — เพิ่มเฝ้าดู (default = ตัวเองถ้าลิงก์แล้ว)\n"
            "• `vrc.unwatch [usr_... | @member]`\n"
            "• `vrc.watchlist`\n"
            "• `vrc.watchclear`\n"
        )
        await ctx.send(embed=em)

    @commands.command(name="vrc.uid")
    async def vrc_uid(self, ctx: commands.Context, user_id: str):
        user_id = user_id.strip()
        if not USER_ID_RE.match(user_id):
            return await ctx.send("รูปแบบไม่ถูกต้องครับ ต้องเป็น `usr_...` (UUID)")

        try:
            u = await self.api.get_user_by_id(user_id)
            embed = await self._build_user_detail_embed(u)
        except VRChatError as e:
            return await ctx.send(f"ดึงข้อมูลไม่สำเร็จ (HTTP {e.status}): {_clip(e.message, 300)}")

        await ctx.send(embed=embed, view=DetailActionsView(self, ctx.author.id, "user", embed, u))

    @commands.command(name="vrc.user")
    async def vrc_user(self, ctx: commands.Context, *, query: str):
        query = query.strip()
        if not query:
            return await ctx.send("ใส่คำค้นก่อนครับ เช่น `vrc.user neko`")

        try:
            items = await self.api.search_users(query, n=60, offset=0)
        except VRChatError as e:
            return await ctx.send(f"ค้นหาไม่สำเร็จ (HTTP {e.status}): {_clip(e.message, 300)}")

        if not items:
            return await ctx.send("ไม่พบ user ตามคำค้นนี้ครับ")

        view = SearchResultsView(self, ctx.author.id, "user", items, per_page=10)
        await ctx.send(embed=view.render_list_embed(), view=view)

    @commands.command(name="vrc.wid")
    async def vrc_wid(self, ctx: commands.Context, world_id: str):
        world_id = world_id.strip()
        if not WORLD_ID_RE.match(world_id):
            return await ctx.send("รูปแบบไม่ถูกต้องครับ ต้องเป็น `wrld_...` (UUID)")

        try:
            w = await self.api.get_world_by_id(world_id)
            embed = self._build_world_detail_embed(w)
        except VRChatError as e:
            return await ctx.send(f"ดึงข้อมูลไม่สำเร็จ (HTTP {e.status}): {_clip(e.message, 300)}")

        await ctx.send(embed=embed, view=DetailActionsView(self, ctx.author.id, "world", embed, w))

    @commands.command(name="vrc.world")
    async def vrc_world(self, ctx: commands.Context, *, query: str):
        query = query.strip()
        if not query:
            return await ctx.send("ใส่คำค้นก่อนครับ เช่น `vrc.world chill`")

        try:
            items = await self.api.search_worlds(query, n=60, offset=0, sort="popularity")
        except VRChatError as e:
            return await ctx.send(f"ค้นหาไม่สำเร็จ (HTTP {e.status}): {_clip(e.message, 300)}")

        if not items:
            return await ctx.send("ไม่พบ world ตามคำค้นนี้ครับ")

        view = SearchResultsView(self, ctx.author.id, "world", items, per_page=10)
        await ctx.send(embed=view.render_list_embed(), view=view)

    @commands.command(name="vrc.link")
    async def vrc_link(self, ctx: commands.Context):
        view = discord.ui.View(timeout=60)

        async def _open_modal(interaction: discord.Interaction):
            if interaction.user.id != ctx.author.id:
                return await interaction.response.send_message("ปุ่มนี้สำหรับคนที่สั่งเท่านั้นครับ", ephemeral=True)
            await interaction.response.send_modal(LinkVRChatModal(self))

        btn = discord.ui.Button(label="Link VRChat ID (usr_...)", style=discord.ButtonStyle.primary)
        btn.callback = _open_modal
        view.add_item(btn)

        await ctx.send("กดปุ่มเพื่อกรอก `usr_...` แล้วบอทจะบันทึกการลิงก์ให้ครับ", view=view)

    @commands.command(name="vrc.me")
    async def vrc_me(self, ctx: commands.Context):
        vid = await self.config.user(ctx.author).vrchat_user_id()
        if not vid:
            return await ctx.send("ยังไม่เคยลิงก์ครับ ใช้ `vrc.link` ก่อน")

        try:
            u = await self.api.get_user_by_id(vid)
            embed = await self._build_user_detail_embed(u, title_prefix="👤 Me")
        except VRChatError as e:
            return await ctx.send(f"ดึงข้อมูลไม่สำเร็จ (HTTP {e.status}): {_clip(e.message, 300)}")

        await ctx.send(embed=embed, view=DetailActionsView(self, ctx.author.id, "user", embed, u))

    @commands.command(name="vrc.profile")
    async def vrc_profile(self, ctx: commands.Context, member: discord.Member):
        vid = await self.config.user(member).vrchat_user_id()
        if not vid:
            return await ctx.send(f"{member.mention} ยังไม่เคยลิงก์ VRChat ID ครับ")

        try:
            u = await self.api.get_user_by_id(vid)
            embed = await self._build_user_detail_embed(u, title_prefix=f"👥 {member.display_name}")
        except VRChatError as e:
            return await ctx.send(f"ดึงข้อมูลไม่สำเร็จ (HTTP {e.status}): {_clip(e.message, 300)}")

        await ctx.send(embed=embed, view=DetailActionsView(self, ctx.author.id, "user", embed, u))

    # -----------------------------
    # Watchlist commands (guild)
    # -----------------------------
    @commands.guild_only()
    @commands.admin_or_permissions(manage_guild=True)
    @commands.command(name="vrc.watchchannel")
    async def vrc_watchchannel(self, ctx: commands.Context, channel: Optional[discord.TextChannel] = None):
        channel = channel or ctx.channel
        await self.config.guild(ctx.guild).watch_channel_id.set(int(channel.id))
        await ctx.send(f"✅ ตั้งห้องแจ้งเตือน watchlist เป็น {channel.mention}")

    def _resolve_watch_target(self, ctx: commands.Context, target: Optional[str]) -> Optional[str]:
        # mention has priority
        if ctx.message.mentions:
            member = ctx.message.mentions[0]
            # sync call not allowed; caller will await in command
            return f"member:{member.id}"

        if target:
            t = target.strip()
            if USER_ID_RE.match(t):
                return t
            # allow plain text that looks like usr_...
            return t

        return "self"

    async def _get_vrchat_id_from_selector(self, ctx: commands.Context, selector: str) -> Optional[str]:
        if selector == "self":
            return await self.config.user(ctx.author).vrchat_user_id()

        if selector.startswith("member:"):
            did = int(selector.split(":", 1)[1])
            member = ctx.guild.get_member(did)
            if not member:
                return None
            return await self.config.user(member).vrchat_user_id()

        # raw
        if USER_ID_RE.match(selector):
            return selector
        return None

    @commands.guild_only()
    @commands.admin_or_permissions(manage_guild=True)
    @commands.command(name="vrc.watch")
    async def vrc_watch(self, ctx: commands.Context, *, target: Optional[str] = None):
        selector = self._resolve_watch_target(ctx, target)
        vid = await self._get_vrchat_id_from_selector(ctx, selector)
        if not vid:
            return await ctx.send("ไม่พบ VRChat userId ครับ (ถ้าเป็นตัวเอง/สมาชิก ต้อง `vrc.link` ก่อน หรือส่ง `usr_...` มาโดยตรง)")

        gconf = self.config.guild(ctx.guild)

        ch_id = await gconf.watch_channel_id()
        if not ch_id:
            # auto set to current channel if not set
            await gconf.watch_channel_id.set(int(ctx.channel.id))

        ids: List[str] = await gconf.watch_user_ids()
        if vid in ids:
            return await ctx.send("รายการนี้อยู่ใน watchlist แล้วครับ")

        ids.append(vid)
        await gconf.watch_user_ids.set(ids)

        # seed last snapshot immediately (reduce false-positive)
        try:
            u = await self.api.get_user_by_id(vid)
            last = await gconf.watch_last()
            if not isinstance(last, dict):
                last = {}
            last[vid] = {
                "displayName": u.get("displayName") or vid,
                "state": str(u.get("state") or ""),
                "status": str(u.get("status") or ""),
                "location": str(u.get("location") or ""),
                "lastSeen": u.get("last_login"),
            }
            await gconf.watch_last.set(last)
        except Exception:
            pass

        await ctx.send(f"✅ เพิ่มเข้า watchlist แล้ว: `{vid}`")

    @commands.guild_only()
    @commands.admin_or_permissions(manage_guild=True)
    @commands.command(name="vrc.unwatch")
    async def vrc_unwatch(self, ctx: commands.Context, *, target: Optional[str] = None):
        selector = self._resolve_watch_target(ctx, target)
        vid = await self._get_vrchat_id_from_selector(ctx, selector)
        if not vid:
            return await ctx.send("ไม่พบ VRChat userId ครับ (ต้องส่ง `usr_...` หรือ mention คนที่ลิงก์ไว้)")

        gconf = self.config.guild(ctx.guild)
        ids: List[str] = await gconf.watch_user_ids()
        if vid not in ids:
            return await ctx.send("รายการนี้ไม่ได้อยู่ใน watchlist ครับ")

        ids = [x for x in ids if x != vid]
        await gconf.watch_user_ids.set(ids)

        last = await gconf.watch_last()
        if isinstance(last, dict) and vid in last:
            last.pop(vid, None)
            await gconf.watch_last.set(last)

        await ctx.send(f"✅ ลบออกจาก watchlist แล้ว: `{vid}`")

    @commands.guild_only()
    @commands.admin_or_permissions(manage_guild=True)
    @commands.command(name="vrc.watchlist")
    async def vrc_watchlist(self, ctx: commands.Context):
        gconf = self.config.guild(ctx.guild)
        ids: List[str] = await gconf.watch_user_ids()
        if not ids:
            return await ctx.send("watchlist ว่างครับ")

        last = await gconf.watch_last()
        lines = []
        for i, uid in enumerate(ids, start=1):
            disp = uid
            if isinstance(last, dict) and uid in last and isinstance(last[uid], dict):
                disp = last[uid].get("displayName") or uid
                st = last[uid].get("state") or ""
                lines.append(f"**{i}.** {disp} {_status_emoji(st)} `{st}`\n`{uid}`")
            else:
                lines.append(f"**{i}.** `unknown`\n`{uid}`")

        em = discord.Embed(title="👀 VRChat Watchlist", description="\n\n".join(lines), color=discord.Color.orange())
        ch_id = await gconf.watch_channel_id()
        em.set_footer(text=f"Notify channel: {ch_id or 'not set'} • use vrc.watchchannel")
        await ctx.send(embed=em)

    @commands.guild_only()
    @commands.admin_or_permissions(manage_guild=True)
    @commands.command(name="vrc.watchclear")
    async def vrc_watchclear(self, ctx: commands.Context):
        gconf = self.config.guild(ctx.guild)
        await gconf.watch_user_ids.set([])
        await gconf.watch_last.set({})
        await ctx.send("✅ ล้าง watchlist แล้ว")
