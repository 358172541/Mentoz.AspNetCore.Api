using System;
using System.Threading;
using System.Threading.Tasks;

namespace Mentoz.AspNetCore.Api
{
    public interface ITransaction : IDisposable
    {
        Task<int> SaveChangesAsync(CancellationToken cancellationToken = default);
    }
}