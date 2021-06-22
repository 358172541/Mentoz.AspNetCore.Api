using System;

namespace Mentoz.AspNetCore.Api
{
    public class TokenException : Exception
    {
        public TokenException(string message) : base(message) { }
    }
}