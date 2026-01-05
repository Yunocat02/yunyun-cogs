from .vrchat import VRChatCog

async def setup(bot):
    await bot.add_cog(VRChatCog(bot))
