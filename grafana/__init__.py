from .grafana import Grafana


async def setup(bot):
    await bot.add_cog(Grafana(bot))
