global using Microsoft.EntityFrameworkCore;
using WebApplication1.Models;
using System.Collections.Generic;

namespace Base_net_project.Data
{
    public class DataContext : DbContext
    {
        public DataContext(DbContextOptions<DataContext> options) : base(options)
        {

        }
        public DbSet<User> Users { get; set; }
        public DbSet<RefreshToken> RefreshTokens { get; set; }

    }
}
