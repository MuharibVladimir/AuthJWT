using AuthJWT.Services.Interfaces;

namespace AuthJWT.Services
{
    public class AuthService : IAuthService
    {
        public async Task<User> RegisterUser(UserDto request)
        {
            var user = new User { Email = request.Email };
            return user;
        }
    }
}
