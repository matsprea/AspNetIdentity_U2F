using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using Org.BouncyCastle.Crypto;

namespace U2F.Server
{
	public interface ICrypto
	{
		bool VerifySignature(X509Certificate2 attestationCertificate, byte[] signedBytes, byte[] signature);

		bool VerifySignature(CngKey publicKey, byte[] signedBytes, byte[] signature);

		bool VerifySignature(byte[] publicKey, byte[] signedBytes, byte[] signature);

		bool VerifySignature(AsymmetricKeyParameter publicKey, byte[] signedBytes, byte[] signature);

		AsymmetricKeyParameter DecodePublicKey(byte[] encodedPublicKey);

		byte[] ComputeSha256(byte[] bytes);
	}
}
