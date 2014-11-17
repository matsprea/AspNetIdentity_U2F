using System;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Asn1.Sec;
using Org.BouncyCastle.Asn1.X9;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Generators;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Math.EC;
using Org.BouncyCastle.Security;

namespace U2F.Server.Impl
{
	public class BouncyCastleCrypto : ICrypto
	{
		private readonly DerObjectIdentifier _curve = SecObjectIdentifiers.SecP256r1;

		public bool VerifySignature(X509Certificate2 attestationCertificate, byte[] signedBytes, byte[] signature)
		{
			var x509 = DotNetUtilities.FromX509Certificate(attestationCertificate);

			return VerifySignature(x509.GetPublicKey(), signedBytes, signature);
		}

		public bool VerifySignature(AsymmetricKeyParameter publicKey, byte[] signedBytes, byte[] signature)
		{
			try
			{
				var signer = SignerUtilities.GetSigner("SHA-256withECDSA");
				signer.Init(false, publicKey);
				signer.BlockUpdate(signedBytes, 0, signedBytes.Length);
				return signer.VerifySignature(signature);
			}
			catch (Exception e)
			{
				throw new U2FException("Error when verifying signature", e);
			}
		}


		public bool VerifySignature(CngKey publicKey, byte[] signedBytes, byte[] signature)
		{
			try
			{

				var ecdsaSignature = new ECDsaCng(publicKey)
				{
					HashAlgorithm = CngAlgorithm.Sha256
				};

				return ecdsaSignature.VerifyData(signedBytes, signature);

			}
			catch (ArgumentException e)
			{
				throw new U2FException("Error when verifying signature", e);
			}
			catch (PlatformNotSupportedException e)
			{
				throw new U2FException("Error when verifying signature", e);
			}
		}

		public bool VerifySignature(byte[] publicKey, byte[] signedBytes, byte[] signature)
		{
			var key = DecodePublicKey(publicKey);

			return VerifySignature(key, signedBytes, signature);
		}


		public AsymmetricKeyParameter DecodePublicKey(byte[] encodedPublicKey)
		{
			try
			{
				var curve = X962NamedCurves.GetByOid(_curve);
				ECPoint point;
				try
				{
					point = curve.Curve.DecodePoint(encodedPublicKey);
				}
				catch (Exception e)
				{
					throw new U2FException("Couldn't parse user public key", e);
				}

				var ecP = new ECDomainParameters(curve.Curve, curve.G, curve.N, curve.H);

				return new ECPublicKeyParameters(point, ecP);
			}
			catch (Exception e)
			{
				throw new U2FException("Error when decoding public key", e);
			}
		}


		public byte[] ComputeSha256(byte[] bytes)
		{
			try
			{
				var mySHA256 = SHA256Cng.Create();
				var hash = mySHA256.ComputeHash(bytes);
				return hash;
			}
			catch (Exception e)
			{
				throw new U2FException("Error when computing SHA-256", e);
			}
		}
	}
}
