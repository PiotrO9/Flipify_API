using System.Net.Mail;
using System.Net;

namespace Flipify.Services
{
    public class EmailService
    {
        private readonly IConfiguration _config;

        public EmailService(IConfiguration config)
        {
            _config = config;
        }

        public void SendVerificationEmail(User user, string token)
        {
            var verificationLink = $"https://localhost:7191/api/auth/verify-email?token={token}";

            var fromAddress = new MailAddress(_config["SmtpSettings:User"], "Flipify");
            var toAddress = new MailAddress(user.Email, user.Username);
            const string subject = "Please verify your email";
            string body = $"Hi {user.Username},\nPlease verify your email by clicking the link below:\n{verificationLink}";

            var smtp = new SmtpClient
            {
                Host = _config["SmtpSettings:Host"],
                Port = int.Parse(_config["SmtpSettings:Port"]),
                EnableSsl = bool.Parse(_config["SmtpSettings:EnableSsl"]),
                DeliveryMethod = SmtpDeliveryMethod.Network,
                UseDefaultCredentials = false,
                Credentials = new NetworkCredential(_config["SmtpSettings:User"], _config["SmtpSettings:Password"])
            };

            using (var message = new MailMessage(fromAddress, toAddress)
            {
                Subject = subject,
                Body = body
            })
            {
                smtp.Send(message);
            }
        }
    }
}
