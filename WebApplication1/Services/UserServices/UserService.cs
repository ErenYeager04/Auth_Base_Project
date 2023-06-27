using Base_net_project.Data;
using WebApplication1.Models;

namespace WebApplication1.Services.UserServices
{
    public class UserService : IUserService
    {
        private readonly DataContext _context;

        public UserService(DataContext context)
        {
            _context = context;
        }
        public User CreateUser(User user)
        {
            _context.Add(user);
            _context.SaveChanges();
            return user;
        }

        public async Task<User> GetUser(int Id)
        {
            try
            {
                var response = await _context.Users.Include(u => u.RefreshToken).FirstOrDefaultAsync(U => U.Id == Id);
                if (response == null)
                {
                    return null;
                }
                return response;
            }
            catch (Exception ex)
            {
                throw new Exception(ex.Message);
            }
        }

        public bool Save()
        {
            var saved = _context.SaveChanges();
            return saved > 0 ? true : false;
        }

        public bool UserExists(int Id)
        {
            return _context.Users.Any(u => u.Id == Id);
        }
    }
}
