using Microsoft.EntityFrameworkCore;

namespace PDF_sign
{
    internal class SqlContext : DbContext
    {
        public DbSet<SqlLog>? Logs { get; set; }
        public DbSet<SqlAuth>? Auth { get; set; }

        public string DbPath { get; }

        public SqlContext()
        {
            DbPath = Path.Join(AppDomain.CurrentDomain.BaseDirectory, "..", "sql.db");
        }

        protected override void OnConfiguring(DbContextOptionsBuilder options)
        {
            options.UseSqlite($"Data Source={DbPath}");
        }
    }
}
