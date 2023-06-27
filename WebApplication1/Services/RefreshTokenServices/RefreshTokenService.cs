using Base_net_project.Data;
using Microsoft.EntityFrameworkCore;
using WebApplication1.Models;

namespace WebApplication1.Services.RefreshTokenServices
{
    public class RefreshTokenService : IRefreshTokenService
    {
        private readonly DataContext _context;

        public RefreshTokenService(DataContext context)
        {
            _context = context;
        }
        public RefreshToken CreateRefreshToken(RefreshToken token)
        {
            _context.Add(token);
            _context.SaveChanges();
            return token;
        }
    }
}
