namespace Auth_API.Models
{
    public class AuthResult
    {
        public string Token { get; set; }
        public bool Result { get; set; }    //success or not
        public List<string> Errors { get; set; }
    }
}
