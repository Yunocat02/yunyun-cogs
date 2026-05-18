from .wynncraft import Wynncraft


async def setup(bot):
    await bot.add_cog(Wynncraft(bot))
