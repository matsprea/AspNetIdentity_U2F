using System.Security.Cryptography;

namespace U2F.Key
{
	public class KeyPair
	{
		public CngKey PublicKey { get; private set; }

		public CngKey PrivateKey { get; private set; }

		public KeyPair(CngKey publicKey, CngKey privateKey)
		{
			PublicKey = publicKey;
			PrivateKey = privateKey;

		}
	}
}