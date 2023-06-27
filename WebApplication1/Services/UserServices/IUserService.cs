using WebApplication1.Models;

namespace WebApplication1.Services.UserServices
{
    public interface IUserService
    {
        bool UserExists(int Id);
        Task<User> GetUser(int Id);
        User CreateUser(User user);
        bool Save();
    }
}
