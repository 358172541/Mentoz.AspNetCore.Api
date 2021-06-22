using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Metadata.Builders;
using System;

namespace Mentoz.AspNetCore.Api
{
    public class UserConfiguration : IEntityTypeConfiguration<User>
    {
        public void Configure(EntityTypeBuilder<User> builder)
        {
            builder.HasKey(x => x.UserId);
            builder.Property(x => x.Account).HasMaxLength(50).IsRequired();
            builder.HasIndex(x => x.Account).IsUnique();
            builder.HasData(new[] {
                new User
                {
                    UserId = Guid.Parse("11111111-1111-1111-1111-111111111111"),
                    Type = UserType.MANAGER,
                    Account = "tester",
                    Password = "tester",
                    Display = "tester",
                    Available = true
                }
            });
        }
    }
}