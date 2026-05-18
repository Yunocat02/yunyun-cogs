import asyncio
import re
import shlex
import urllib.parse
from io import BytesIO
from typing import Any, Dict, Optional, Tuple

import aiohttp
import discord
from redbot.core import Config, checks, commands


RESERVED_OPTIONS = {
    "from",
    "to",
    "range",
    "width",
    "height",
    "tz",
    "theme",
    "orgid",
    "org_id",
    "slug",
    "timeout",
}

VALID_THEMES = {"light", "dark"}

MIN_WIDTH = 300
MAX_WIDTH = 2400
MIN_HEIGHT = 200
MAX_HEIGHT = 1600
MIN_TIMEOUT = 10
MAX_TIMEOUT = 180


def _clean_base_url(url: str) -> str:
    """Normalize Grafana base URL."""
    url = (url or "").strip()
    if not url:
        return ""

    if not url.startswith(("http://", "https://")):
        url = "http://" + url

    return url.rstrip("/")


def _safe_name(name: str) -> str:
    """Create a safe short key/file name."""
    cleaned = re.sub(r"[^a-zA-Z0-9_.-]", "_", (name or "").strip().lower())
    cleaned = re.sub(r"_+", "_", cleaned).strip("._-")
    return cleaned[:80]


def _safe_text(text: str, limit: int = 1200) -> str:
    """Make response text safe for Discord code blocks."""
    text = (text or "").replace("```", "`\u200b``")
    return text[:limit]


def _parse_kv_options(raw: str) -> Dict[str, str]:
    """
    Parse key=value options.

    Supports normal space-separated options and simple quoted values:
      range=6h var-job=node var-node=node-exporter:9100 width=1200
      from=now-24h to=now "var-env=prod app"
    """
    result: Dict[str, str] = {}
    if not raw:
        return result

    try:
        parts = shlex.split(raw)
    except ValueError:
        # Fallback for unmatched quotes; better to ignore bad quoting than crash the command.
        parts = raw.split()

    for part in parts:
        if "=" not in part:
            continue

        key, value = part.split("=", 1)
        key = key.strip()
        value = value.strip()

        if key:
            result[key] = value

    return result


def _normalize_vars(options: Dict[str, str]) -> Tuple[Dict[str, str], Dict[str, str]]:
    """
    Split options into Grafana render options and dashboard template variables.

    Reserved keys are used by the render endpoint.
    Other keys become Grafana variables and are sent as var-<name>=<value>.
    """
    render_opts: Dict[str, str] = {}
    variables: Dict[str, str] = {}

    for key, value in options.items():
        original_key = key.strip()
        lower_key = original_key.lower()

        if lower_key in RESERVED_OPTIONS:
            render_opts[lower_key] = value
            continue

        if lower_key.startswith("var-"):
            var_key = original_key[4:].strip()
        else:
            var_key = original_key

        if var_key:
            variables[var_key] = value

    return render_opts, variables


def _parse_int_option(
    value: Any,
    option_name: str,
    minimum: int,
    maximum: int,
) -> int:
    try:
        parsed = int(value)
    except (TypeError, ValueError):
        raise ValueError(f"{option_name} ต้องเป็นตัวเลขครับ")

    if parsed < minimum or parsed > maximum:
        raise ValueError(f"{option_name} ต้องอยู่ระหว่าง {minimum}-{maximum} ครับ")

    return parsed


class Grafana(commands.Cog):
    """
    Render Grafana panels to Discord.

    Main commands:
      [p]grafana endpoint http://<grafana-host>:3002
      [p]grafana panel_add cpu <dashboard_uid> <panel_id>
      [p]grafana graph cpu range=6h var-job=node var-node=<node-exporter-host>:9100
    """

    def __init__(self, bot):
        self.bot = bot
        self.config = Config.get_conf(self, identifier=3000000001, force_registration=True)
        self.config.register_global(
            endpoint="",
            api_token=None,
            org_id=1,
            timezone="Asia/Bangkok",
            theme="light",
            width=1000,
            height=500,
            timeout=60,
            default_vars={},
            panels={},
        )

    async def cog_unload(self):
        pass

    @commands.group(name="grafana", aliases=["gf"])
    async def grafana(self, ctx: commands.Context):
        """Grafana render commands."""
        if ctx.invoked_subcommand is None:
            await ctx.send_help(ctx.command)

    @grafana.command(name="endpoint")
    @checks.admin_or_permissions(manage_guild=True)
    async def endpoint(self, ctx: commands.Context, endpoint: str):
        """Set Grafana endpoint. Example: [p]grafana endpoint http://<grafana-host>:3002"""
        endpoint = _clean_base_url(endpoint)
        if not endpoint:
            await ctx.send("❌ Endpoint ว่างครับ")
            return

        await self.config.endpoint.set(endpoint)
        await ctx.send(f"✅ ตั้ง Grafana endpoint เป็น `{endpoint}` แล้วครับ")

    @grafana.command(name="token")
    @checks.admin_or_permissions(manage_guild=True)
    async def token(self, ctx: commands.Context, *, token: str):
        """Set Grafana API token. Prefer running this in a private/admin channel."""
        token = token.strip()
        if not token:
            await ctx.send("❌ Token ว่างครับ")
            return

        await self.config.api_token.set(token)

        try:
            await ctx.message.delete()
        except discord.Forbidden:
            pass
        except discord.HTTPException:
            pass

        await ctx.send("✅ ตั้ง Grafana API token แล้วครับ ข้อความ command ถูกลบถ้าบอทมีสิทธิ์ลบข้อความ")

    @grafana.command(name="token_clear")
    @checks.admin_or_permissions(manage_guild=True)
    async def token_clear(self, ctx: commands.Context):
        """Clear Grafana API token."""
        await self.config.api_token.set(None)
        await ctx.send("✅ ลบ Grafana API token แล้วครับ")

    @grafana.command(name="org")
    @checks.admin_or_permissions(manage_guild=True)
    async def org(self, ctx: commands.Context, org_id: int):
        """Set Grafana orgId."""
        if org_id < 1:
            await ctx.send("❌ orgId ต้องมากกว่า 0 ครับ")
            return

        await self.config.org_id.set(org_id)
        await ctx.send(f"✅ ตั้ง orgId เป็น `{org_id}` แล้วครับ")

    @grafana.command(name="tz")
    @checks.admin_or_permissions(manage_guild=True)
    async def tz(self, ctx: commands.Context, timezone: str):
        """Set default timezone. Example: Asia/Bangkok"""
        timezone = timezone.strip()
        if not timezone:
            await ctx.send("❌ timezone ว่างครับ")
            return

        await self.config.timezone.set(timezone)
        await ctx.send(f"✅ ตั้ง timezone เป็น `{timezone}` แล้วครับ")

    @grafana.command(name="theme")
    @checks.admin_or_permissions(manage_guild=True)
    async def theme(self, ctx: commands.Context, theme: str):
        """Set default Grafana theme: light or dark."""
        theme = theme.strip().lower()
        if theme not in VALID_THEMES:
            await ctx.send("❌ theme ต้องเป็น `light` หรือ `dark` ครับ")
            return

        await self.config.theme.set(theme)
        await ctx.send(f"✅ ตั้ง theme เป็น `{theme}` แล้วครับ")

    @grafana.command(name="size")
    @checks.admin_or_permissions(manage_guild=True)
    async def size(self, ctx: commands.Context, width: int, height: int):
        """Set default render image size."""
        try:
            width = _parse_int_option(width, "width", MIN_WIDTH, MAX_WIDTH)
            height = _parse_int_option(height, "height", MIN_HEIGHT, MAX_HEIGHT)
        except ValueError as exc:
            await ctx.send(f"❌ {exc}")
            return

        await self.config.width.set(width)
        await self.config.height.set(height)
        await ctx.send(f"✅ ตั้งขนาดรูป default เป็น `{width}x{height}` แล้วครับ")

    @grafana.command(name="timeout")
    @checks.admin_or_permissions(manage_guild=True)
    async def timeout(self, ctx: commands.Context, seconds: int):
        """Set HTTP timeout for rendering."""
        try:
            seconds = _parse_int_option(seconds, "timeout", MIN_TIMEOUT, MAX_TIMEOUT)
        except ValueError as exc:
            await ctx.send(f"❌ {exc}")
            return

        await self.config.timeout.set(seconds)
        await ctx.send(f"✅ ตั้ง timeout เป็น `{seconds}` วินาทีแล้วครับ")

    @grafana.command(name="panel_add")
    @checks.admin_or_permissions(manage_guild=True)
    async def panel_add(
        self,
        ctx: commands.Context,
        name: str,
        dashboard_uid: str,
        panel_id: int,
        slug: Optional[str] = "dashboard",
    ):
        """
        Add panel shortcut.

        Example:
          [p]grafana panel_add cpu linux123 2 linux-monitoring
        """
        key = _safe_name(name)
        dashboard_uid = dashboard_uid.strip()
        slug = (slug or "dashboard").strip().strip("/") or "dashboard"

        if not key:
            await ctx.send("❌ ชื่อ panel ไม่ถูกต้องครับ")
            return
        if not dashboard_uid:
            await ctx.send("❌ dashboard_uid ว่างครับ")
            return
        if panel_id < 1:
            await ctx.send("❌ panel_id ต้องมากกว่า 0 ครับ")
            return

        panels = await self.config.panels()
        panels[key] = {
            "dashboard_uid": dashboard_uid,
            "panel_id": int(panel_id),
            "slug": slug,
        }
        await self.config.panels.set(panels)

        await ctx.send(
            f"✅ เพิ่ม panel `{key}` แล้วครับ "
            f"(uid=`{dashboard_uid}`, panelId=`{panel_id}`, slug=`{slug}`)"
        )

    @grafana.command(name="panel_del", aliases=["panel_remove"])
    @checks.admin_or_permissions(manage_guild=True)
    async def panel_del(self, ctx: commands.Context, name: str):
        """Delete panel shortcut."""
        key = _safe_name(name)
        panels = await self.config.panels()

        if key not in panels:
            await ctx.send(f"❌ ไม่พบ panel `{key}` ครับ")
            return

        panels.pop(key)
        await self.config.panels.set(panels)
        await ctx.send(f"✅ ลบ panel `{key}` แล้วครับ")

    @grafana.command(name="panel_list")
    async def panel_list(self, ctx: commands.Context):
        """List saved panels."""
        panels = await self.config.panels()
        if not panels:
            await ctx.send("ยังไม่มี panel ที่บันทึกไว้ครับ ใช้ `[p]grafana panel_add <name> <uid> <panel_id>`")
            return

        lines = []
        for name, item in sorted(panels.items()):
            lines.append(
                f"`{name}` → uid=`{item.get('dashboard_uid')}`, "
                f"panelId=`{item.get('panel_id')}`, slug=`{item.get('slug', 'dashboard')}`"
            )

        embed = discord.Embed(
            title="Grafana Panels",
            description="\n".join(lines[:30]),
            color=discord.Color.blue(),
        )
        if len(lines) > 30:
            embed.set_footer(text=f"แสดง 30 รายการแรก จากทั้งหมด {len(lines)} รายการ")

        await ctx.send(embed=embed)

    @grafana.command(name="defaultvar")
    @checks.admin_or_permissions(manage_guild=True)
    async def defaultvar(self, ctx: commands.Context, key: str, *, value: str):
        """
        Set default Grafana variable.

        Example:
          [p]grafana defaultvar job node
          [p]grafana defaultvar node <node-exporter-host>:9100
        """
        key = key.strip()
        value = value.strip()

        if key.lower().startswith("var-"):
            key = key[4:].strip()

        if not key:
            await ctx.send("❌ variable key ว่างครับ")
            return

        default_vars = await self.config.default_vars()
        default_vars[key] = value
        await self.config.default_vars.set(default_vars)

        await ctx.send(f"✅ ตั้ง default variable `var-{key}` = `{value}` แล้วครับ")

    @grafana.command(name="defaultvar_del")
    @checks.admin_or_permissions(manage_guild=True)
    async def defaultvar_del(self, ctx: commands.Context, key: str):
        """Delete default Grafana variable."""
        key = key.strip()
        if key.lower().startswith("var-"):
            key = key[4:].strip()

        default_vars = await self.config.default_vars()
        if key not in default_vars:
            await ctx.send(f"❌ ไม่พบ default variable `{key}` ครับ")
            return

        default_vars.pop(key)
        await self.config.default_vars.set(default_vars)
        await ctx.send(f"✅ ลบ default variable `var-{key}` แล้วครับ")

    @grafana.command(name="defaultvars")
    async def defaultvars(self, ctx: commands.Context):
        """List default Grafana variables."""
        default_vars = await self.config.default_vars()
        if not default_vars:
            await ctx.send("ยังไม่มี default variables ครับ")
            return

        lines = [f"`var-{k}` = `{v}`" for k, v in sorted(default_vars.items())]
        embed = discord.Embed(
            title="Grafana Default Variables",
            description="\n".join(lines[:40]),
            color=discord.Color.green(),
        )

        if len(lines) > 40:
            embed.set_footer(text=f"แสดง 40 รายการแรก จากทั้งหมด {len(lines)} รายการ")

        await ctx.send(embed=embed)

    @grafana.command(name="settings")
    async def settings(self, ctx: commands.Context):
        """Show current Grafana cog settings."""
        endpoint = await self.config.endpoint()
        org_id = await self.config.org_id()
        timezone = await self.config.timezone()
        theme = await self.config.theme()
        width = await self.config.width()
        height = await self.config.height()
        timeout = await self.config.timeout()
        token = await self.config.api_token()
        panels = await self.config.panels()
        default_vars = await self.config.default_vars()

        embed = discord.Embed(title="Grafana Settings", color=discord.Color.blurple())
        embed.add_field(name="Endpoint", value=f"`{endpoint or 'Not set'}`", inline=False)
        embed.add_field(name="API Token", value="✅ Set" if token else "❌ Not set", inline=True)
        embed.add_field(name="orgId", value=f"`{org_id}`", inline=True)
        embed.add_field(name="Timezone", value=f"`{timezone}`", inline=True)
        embed.add_field(name="Theme", value=f"`{theme}`", inline=True)
        embed.add_field(name="Size", value=f"`{width}x{height}`", inline=True)
        embed.add_field(name="Timeout", value=f"`{timeout}s`", inline=True)
        embed.add_field(name="Panels", value=f"`{len(panels)}`", inline=True)
        embed.add_field(name="Default Vars", value=f"`{len(default_vars)}`", inline=True)

        await ctx.send(embed=embed)

    @grafana.command(name="ping")
    async def ping(self, ctx: commands.Context):
        """Check Grafana health from Discord bot."""
        endpoint = _clean_base_url(await self.config.endpoint())
        if not endpoint:
            await ctx.send("❌ ยังไม่ได้ตั้ง endpoint ครับ")
            return

        url = f"{endpoint}/api/health"
        try:
            data, status, content_type = await self._http_get(url, expect_image=False)
        except asyncio.TimeoutError:
            timeout = await self.config.timeout()
            await ctx.send(f"❌ ติดต่อ Grafana timeout เกิน `{timeout}` วินาทีครับ")
            return
        except aiohttp.ClientConnectorError as exc:
            await ctx.send(f"❌ ติดต่อ Grafana ไม่สำเร็จ: `{exc}`")
            return
        except aiohttp.ClientError as exc:
            await ctx.send(f"❌ HTTP error จาก Grafana: `{type(exc).__name__}: {exc}`")
            return

        text = _safe_text(data.decode("utf-8", errors="replace"), 1000)
        if status >= 400:
            await ctx.send(f"❌ Grafana ตอบกลับ status `{status}` จาก `{url}`\n```text\n{text}\n```")
            return

        await ctx.send(f"✅ Grafana reachable: status `{status}`, content-type=`{content_type}`\n```json\n{text}\n```")

    @grafana.command(name="graph")
    async def graph(self, ctx: commands.Context, name: str, *, raw_options: str = ""):
        """
        Render saved Grafana panel.

        Examples:
          [p]grafana graph cpu
          [p]grafana graph cpu range=6h var-job=node var-node=<node-exporter-host>:9100
          [p]grafana graph cpu from=now-24h to=now width=1400 height=700
        """
        key = _safe_name(name)
        panels = await self.config.panels()
        if key not in panels:
            await ctx.send(f"❌ ไม่พบ panel `{key}` ครับ ใช้ `[p]grafana panel_list` เพื่อตรวจสอบ")
            return

        item = panels[key]
        await self._render_and_send(
            ctx=ctx,
            dashboard_uid=str(item["dashboard_uid"]),
            panel_id=int(item["panel_id"]),
            slug=str(item.get("slug", "dashboard")),
            raw_options=raw_options,
            filename_prefix=key,
        )

    @grafana.command(name="render")
    async def render(
        self,
        ctx: commands.Context,
        dashboard_uid: str,
        panel_id: int,
        *,
        raw_options: str = "",
    ):
        """
        Render Grafana panel directly without saving shortcut.

        Example:
          [p]grafana render abc123 4 range=24h var-job=node
        """
        if panel_id < 1:
            await ctx.send("❌ panel_id ต้องมากกว่า 0 ครับ")
            return

        await self._render_and_send(
            ctx=ctx,
            dashboard_uid=dashboard_uid,
            panel_id=panel_id,
            slug="dashboard",
            raw_options=raw_options,
            filename_prefix=f"{dashboard_uid}_{panel_id}",
        )

    @grafana.command(name="test")
    async def test(self, ctx: commands.Context, name: str):
        """Test saved panel rendering with default options."""
        key = _safe_name(name)
        panels = await self.config.panels()
        if key not in panels:
            await ctx.send(f"❌ ไม่พบ panel `{key}` ครับ ใช้ `[p]grafana panel_list` เพื่อตรวจสอบ")
            return

        item = panels[key]
        await self._render_and_send(
            ctx=ctx,
            dashboard_uid=str(item["dashboard_uid"]),
            panel_id=int(item["panel_id"]),
            slug=str(item.get("slug", "dashboard")),
            raw_options="range=1h width=900 height=450",
            filename_prefix=key,
        )

    async def _render_and_send(
        self,
        ctx: commands.Context,
        dashboard_uid: str,
        panel_id: int,
        slug: str,
        raw_options: str,
        filename_prefix: str,
    ):
        async with ctx.typing():
            try:
                url, timeout_override = await self._build_render_url(
                    dashboard_uid=dashboard_uid,
                    panel_id=panel_id,
                    slug=slug,
                    raw_options=raw_options,
                )

                image_bytes, status, content_type = await self._http_get(
                    url,
                    expect_image=True,
                    timeout_override=timeout_override,
                )

                if status >= 400:
                    text = _safe_text(image_bytes.decode("utf-8", errors="replace"))
                    await ctx.send(
                        f"❌ Render failed: HTTP `{status}`\n"
                        f"URL: `{self._mask_url(url)}`\n"
                        f"Response:\n```text\n{text}\n```"
                    )
                    return

                if not content_type.lower().startswith("image/"):
                    text = _safe_text(image_bytes.decode("utf-8", errors="replace"))
                    await ctx.send(
                        f"❌ Grafana ไม่ได้ส่งรูปภาพกลับมา content-type=`{content_type}`\n"
                        f"URL: `{self._mask_url(url)}`\n"
                        f"Response:\n```text\n{text}\n```"
                    )
                    return

                max_size = getattr(ctx.guild, "filesize_limit", 8 * 1024 * 1024) if ctx.guild else 8 * 1024 * 1024
                if len(image_bytes) > max_size:
                    await ctx.send(
                        f"❌ รูปใหญ่เกิน limit ของ Discord ครับ "
                        f"ขนาดรูป `{len(image_bytes) / 1024 / 1024:.2f} MB`, "
                        f"limit `{max_size / 1024 / 1024:.2f} MB` "
                        f"ลองลด `width`/`height` หรือช่วงเวลา `range`"
                    )
                    return

                filename = f"grafana_{_safe_name(filename_prefix)}.png"
                file = discord.File(BytesIO(image_bytes), filename=filename)

                embed = discord.Embed(
                    title=f"Grafana: {filename_prefix}",
                    description=f"`panelId={panel_id}`",
                    color=discord.Color.dark_teal(),
                )
                embed.set_image(url=f"attachment://{filename}")
                embed.set_footer(text="Rendered from Grafana")
                await ctx.send(embed=embed, file=file)

            except asyncio.TimeoutError:
                timeout = timeout_override if "timeout_override" in locals() and timeout_override else await self.config.timeout()
                await ctx.send(f"❌ Render timeout เกิน `{timeout}` วินาทีครับ ลองลด width/height หรือเพิ่ม timeout")
            except aiohttp.ClientConnectorError as exc:
                await ctx.send(f"❌ เชื่อมต่อ Grafana ไม่ได้ครับ: `{exc}`")
            except aiohttp.ClientError as exc:
                await ctx.send(f"❌ HTTP error จาก Grafana: `{type(exc).__name__}: {exc}`")
            except ValueError as exc:
                await ctx.send(f"❌ Config หรือ options ไม่ถูกต้อง: `{exc}`")
            except discord.HTTPException as exc:
                await ctx.send(f"❌ ส่งรูปเข้า Discord ไม่สำเร็จ: `{exc}`")
            except Exception as exc:
                await ctx.send(f"❌ เกิดข้อผิดพลาด: `{type(exc).__name__}: {exc}`")

    async def _build_render_url(
        self,
        dashboard_uid: str,
        panel_id: int,
        slug: str,
        raw_options: str,
    ) -> Tuple[str, Optional[int]]:
        endpoint = _clean_base_url(await self.config.endpoint())
        org_id = await self.config.org_id()
        timezone = await self.config.timezone()
        theme = await self.config.theme()
        default_width = await self.config.width()
        default_height = await self.config.height()
        default_vars = await self.config.default_vars()

        if not endpoint:
            raise ValueError("Grafana endpoint is not configured")

        dashboard_uid = dashboard_uid.strip()
        if not dashboard_uid:
            raise ValueError("dashboard_uid ว่างครับ")

        if panel_id < 1:
            raise ValueError("panel_id ต้องมากกว่า 0 ครับ")

        options = _parse_kv_options(raw_options)
        render_opts, variables = _normalize_vars(options)

        # range=6h is shorthand for from=now-6h to=now
        range_value = render_opts.get("range")
        if range_value:
            from_value = f"now-{range_value}"
            to_value = "now"
        else:
            from_value = render_opts.get("from", "now-6h")
            to_value = render_opts.get("to", "now")

        width = _parse_int_option(render_opts.get("width", default_width), "width", MIN_WIDTH, MAX_WIDTH)
        height = _parse_int_option(render_opts.get("height", default_height), "height", MIN_HEIGHT, MAX_HEIGHT)
        timeout_override = None

        if "timeout" in render_opts:
            timeout_override = _parse_int_option(render_opts["timeout"], "timeout", MIN_TIMEOUT, MAX_TIMEOUT)

        tz = render_opts.get("tz", timezone).strip() or "Asia/Bangkok"
        theme = render_opts.get("theme", theme).strip().lower()
        if theme not in VALID_THEMES:
            raise ValueError("theme ต้องเป็น light หรือ dark ครับ")

        org_value = render_opts.get("orgid", render_opts.get("org_id", org_id))
        org_id = _parse_int_option(org_value, "orgId", 1, 999999)

        slug = render_opts.get("slug", slug or "dashboard").strip().strip("/") or "dashboard"

        merged_vars = dict(default_vars)
        merged_vars.update(variables)

        query: Dict[str, Any] = {
            "orgId": org_id,
            "panelId": panel_id,
            "from": from_value,
            "to": to_value,
            "width": width,
            "height": height,
            "tz": tz,
            "theme": theme,
        }

        for key, value in merged_vars.items():
            clean_key = key[4:] if key.lower().startswith("var-") else key
            clean_key = clean_key.strip()
            if clean_key:
                query[f"var-{clean_key}"] = value

        encoded_slug = urllib.parse.quote(slug, safe="")
        encoded_uid = urllib.parse.quote(dashboard_uid, safe="")

        url = f"{endpoint}/render/d-solo/{encoded_uid}/{encoded_slug}?{urllib.parse.urlencode(query)}"
        return url, timeout_override

    async def _http_get(
        self,
        url: str,
        expect_image: bool,
        timeout_override: Optional[int] = None,
    ) -> Tuple[bytes, int, str]:
        timeout_seconds = timeout_override or await self.config.timeout()
        token = await self.config.api_token()

        headers = {
            "User-Agent": "Red-DiscordBot-Grafana-Cog/1.1",
        }

        if expect_image:
            headers["Accept"] = "image/png,image/*;q=0.9,*/*;q=0.1"
        else:
            headers["Accept"] = "application/json,text/plain,*/*"

        if token:
            headers["Authorization"] = f"Bearer {token}"

        timeout = aiohttp.ClientTimeout(total=timeout_seconds)
        async with aiohttp.ClientSession(timeout=timeout, headers=headers) as session:
            async with session.get(url) as resp:
                data = await resp.read()
                content_type = resp.headers.get("Content-Type", "application/octet-stream").split(";")[0]
                return data, resp.status, content_type

    def _mask_url(self, url: str) -> str:
        # The URL should not contain the Bearer token, but keep masking for future safety.
        return re.sub(r"(?i)(renderKey|auth_token|token)=([^&]+)", r"\1=***", url)
