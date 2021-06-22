using System;

namespace Mentoz.AspNetCore.Api
{
    public class ValidationException : Exception
    {
        public ValidationException(string message) : base(message) { }
    }
}