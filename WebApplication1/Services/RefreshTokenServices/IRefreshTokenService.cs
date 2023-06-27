using WebApplication1.Models;

namespace WebApplication1.Services.RefreshTokenServices
{
    public interface IRefreshTokenService
    {
        RefreshToken CreateRefreshToken(RefreshToken token);
    }
}
