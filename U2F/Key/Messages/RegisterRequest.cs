using System.Collections.Generic;

namespace U2F.Key.Messages
{
	public class RegisterRequest : U2FRequest, IEqualityComparer<RegisterRequest>
	{
		/**
		* The challenge parameter is the SHA-256 hash of the Client Data, a
		* stringified JSON datastructure that the FIDO Client prepares. Among other
		* things, the Client Data contains the challenge from the relying party
		* (hence the name of the parameter). See below for a detailed explanation of
		* Client Data.
		*/
		public byte[] ChallengeSha256 { get; private set; }

		/**
		* The application parameter is the SHA-256 hash of the application identity
		* of the application requesting the registration
		*/
		public byte[] ApplicationSha256 { get; private set; }

		public RegisterRequest(byte[] applicationSha256, byte[] challengeSha256)
		{
			ChallengeSha256 = challengeSha256;
			ApplicationSha256 = applicationSha256;
		}

		public bool Equals(RegisterRequest x, RegisterRequest y)
		{
			if (x == y)
				return true;
			if (y == null)
				return false;
			if (!x.ApplicationSha256.Equals(y.ApplicationSha256))
				return false;
			if (!x.ChallengeSha256.Equals(y.ChallengeSha256))
				return false;
			return true;
		}

		public int GetHashCode(RegisterRequest obj)
		{
			const int prime = 31;
			var result = 1;
			result = prime*result + ApplicationSha256.GetHashCode();
			result = prime*result + ChallengeSha256.GetHashCode();
			return result;
		}
	}
}