using System.Collections.Generic;

namespace U2F.Key.Messages
{
	public class AuthenticateRequest : U2FRequest, IEqualityComparer<AuthenticateRequest>
	{
		public const byte CHECK_ONLY = 0x07;
		public const byte USER_PRESENCE_SIGN = 0x03;

		/** The FIDO Client will set the control byte to one of the following values:
		* 0x07 ("check-only")
		*0x03 ("enforce-user-presence-and-sign")
		*/
		public byte Control { get; private set; }

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

		/** The key handle obtained during registration. */
		public byte[] KeyHandle { get; private set; }

		public AuthenticateRequest(byte control, byte[] challengeSha256, byte[] applicationSha256,
			byte[] keyHandle)
		{
			Control = control;
			ChallengeSha256 = challengeSha256;
			ApplicationSha256 = applicationSha256;
			KeyHandle = keyHandle;
		}

		public bool Equals(AuthenticateRequest x, AuthenticateRequest y)
		{
			if (x == y)
				return true;
			if (y == null)
				return false;
			if (!x.ApplicationSha256.Equals(y.ApplicationSha256))
				return false;
			if (!x.ChallengeSha256.Equals(y.ChallengeSha256))
				return false;
			if (x.Control != y.Control)
				return false;
			if (!x.KeyHandle.Equals(y.KeyHandle))
				return false;
			return true;
		}

		public int GetHashCode(AuthenticateRequest obj)
		{
			const int prime = 31;
			var result = 1;
			result = prime*result + ApplicationSha256.GetHashCode();
			result = prime*result + ChallengeSha256.GetHashCode();
			result = prime*result + Control;
			result = prime*result + KeyHandle.GetHashCode();
			return result;
		}
	}
}
