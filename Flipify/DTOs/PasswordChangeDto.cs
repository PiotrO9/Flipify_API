namespace Flipify.DTOs
{
    public class RequestPasswordChangeDto
    {
        public string Email { get; set; }
    }

    public class ConfirmPasswordChangeDto
    {
        public string Token { get; set; }
        public string NewPassword { get; set; }
    }
}
