using System;

namespace U2F.Server.Data
{
	public class SignSessionData : EnrollSessionData {
		private const long SerialVersionUid = -1374014642398686120L;

		public byte[] PublicKey { get; private set; }

		public SignSessionData(String accountName, String appId, byte[] challenge, byte[] publicKey)
			: base(accountName, appId, challenge)
		{
			PublicKey = publicKey;
		}
	}
}