from .autorejoin import AutoRejoin

async def setup(bot):
    await bot.add_cog(AutoRejoin(bot))
