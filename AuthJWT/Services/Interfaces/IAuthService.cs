namespace AuthJWT.Services.Interfaces
{
    public interface IAuthService
    {
        Task<User> RegisterUser(UserDto request);
    }
}
