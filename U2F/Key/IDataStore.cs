using Org.BouncyCastle.Bcpg.OpenPgp;

namespace U2F.Key
{
	public interface IDataStore
	{
		void StoreKeyPair(byte[] keyHandle, PgpKeyPair keyPair);

		KeyPair GetKeyPair(byte[] keyHandle);

		int IncrementCounter();
	}
}
