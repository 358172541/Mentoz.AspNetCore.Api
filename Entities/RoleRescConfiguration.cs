using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Metadata.Builders;

namespace Mentoz.AspNetCore.Api
{
    public class RoleRescConfiguration : IEntityTypeConfiguration<RoleResc>
    {
        public void Configure(EntityTypeBuilder<RoleResc> builder)
        {
            builder.HasKey(x => new { x.RoleId, x.RescId });
        }
    }
}