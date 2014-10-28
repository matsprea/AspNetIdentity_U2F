using System.Security.Cryptography;

namespace U2F.Key
{
	public interface ICrypto
	{
		byte[] Sign(byte[] signedData, CngKey certificatePrivateKey);
	}
}
