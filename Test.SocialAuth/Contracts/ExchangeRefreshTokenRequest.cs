namespace Test.SocialAuth.Contracts
{
    public class ExchangeRefreshTokenRequest
    {
        public string AccessToken { get; set; }
        public string RefreshToken { get; set; }
    }
}
