using System.Threading.Tasks;
using IdentitySample.Models;
using Microsoft.AspNet.Identity;

namespace AspNetIdentity_U2F
{
	public class U2FTokenProvider : IUserTokenProvider<ApplicationUser, string>
	{
		public Task<string> GenerateAsync(string purpose, UserManager<ApplicationUser, string> manager, ApplicationUser user)
		{
			return Task.FromResult((string)null);
		}

		public Task<bool> ValidateAsync(string purpose, string token, UserManager<ApplicationUser, string> manager, ApplicationUser user)
		{
			long timeStepMatched = 0;
/*
			var otp = new Totp(Base32Encoder.Decode(user.GoogleAuthenticatorSecretKey));
			bool valid = otp.VerifyTotp(token, out timeStepMatched, new VerificationWindow(2, 2));
			*/
			bool valid = true;

			return Task.FromResult(valid);
		}

		public Task NotifyAsync(string token, UserManager<ApplicationUser, string> manager, ApplicationUser user)
		{
			return Task.FromResult(true);
		}

		public Task<bool> IsValidProviderForUserAsync(UserManager<ApplicationUser, string> manager, ApplicationUser user)
		{
			return Task.FromResult(true);
			//return Task.FromResult(user.IsGoogleAuthenticatorEnabled);
		}
	}
}