using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography.X509Certificates;

namespace U2F.Key.Messages
{
	public class RegisterResponse : U2FResponse, IEqualityComparer<RegisterResponse>
	{
		/**
		* This is the (uncompressed) x,y-representation of a curve point on the P-256
		* NIST elliptic curve.
		*/
		public byte[] UserPublicKey { get; private set; }

		/**
		* This a handle that allows the U2F token to identify the generated key pair.
		* U2F tokens MAY wrap the generated private key and the application id it was
		* generated for, and output that as the key handle.
		*/
		public byte[] KeyHandle { get; private set; }

		/**
		* This is a X.509 certificate.
		*/
		public X509Certificate2 AttestationCertificate { get; private set; }

		/** This is a ECDSA signature (on P-256) */
		public byte[] Signature { get; private set; }

		public RegisterResponse(byte[] userPublicKey, byte[] keyHandle,
			X509Certificate2 attestationCertificate, byte[] signature)
		{

			UserPublicKey = userPublicKey;
			KeyHandle = keyHandle;
			AttestationCertificate = attestationCertificate;
			Signature = signature;
		}

		public bool Equals(RegisterResponse x, RegisterResponse y)
		{
			if (x == y)
				return true;
			if (y == null)
				return false;

			if (!x.AttestationCertificate.Equals(y.AttestationCertificate))
				return false;
			if (!x.KeyHandle.SequenceEqual(y.KeyHandle))
				return false;
			if (!x.Signature.SequenceEqual(y.Signature))
				return false;
			if (!x.UserPublicKey.SequenceEqual(y.UserPublicKey))
				return false;
			return true;
		}

		public int GetHashCode(RegisterResponse obj)
		{
			const int prime = 31;
			var result = 1;
			result = prime*result + AttestationCertificate.GetHashCode();
			result = prime*result + KeyHandle.GetHashCode();
			result = prime*result + Signature.GetHashCode();
			result = prime*result + UserPublicKey.GetHashCode();
			return result;
		}
	}
}