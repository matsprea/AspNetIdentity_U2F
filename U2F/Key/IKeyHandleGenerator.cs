using Org.BouncyCastle.Bcpg.OpenPgp;

namespace U2F.Key
{
	public interface IKeyHandleGenerator
	{
		byte[] GenerateKeyHandle(byte[] applicationSha256, PgpKeyPair keyPair);
	}
}
