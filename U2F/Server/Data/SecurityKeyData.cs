using System;
using System.Collections.Generic;
using System.Security.Cryptography.X509Certificates;
using System.Text;

namespace U2F.Server.Data
{
	public class SecurityKeyData : IEqualityComparer<SecurityKeyData>
	{
		public long EnrollmentTime { get; private set; }
		public byte[] KeyHandle { get; private set; }
		public byte[] PublicKey { get; private set; }
		public X509Certificate AttestationCert { get; set; }
		public int Counter { get; set; }

		public SecurityKeyData(
			long enrollmentTime,
			byte[] keyHandle,
			byte[] publicKey,
			X509Certificate attestationCert,
			int counter)
		{
			EnrollmentTime = enrollmentTime;
			KeyHandle = keyHandle;
			PublicKey = publicKey;
			AttestationCert = attestationCert;
			Counter = counter;
		}

		/**
   * When these keys were created/enrolled with the relying party.
   */
		public override String ToString()
		{
			return new StringBuilder()
				.Append("public_key: ")
				.Append(PublicKey.Base64Urlencode())
				.Append("\n")
				.Append("key_handle: ")
				.Append(KeyHandle.Base64Urlencode())
				.Append("\n")
				.Append("counter: ")
				.Append(Counter)
				.Append("\n")
				.Append("attestation certificate:\n")
				.Append(AttestationCert)
				.ToString();
		}

		public bool Equals(SecurityKeyData x, SecurityKeyData y)
		{
			if (x == y)
				return true;
			if (y == null)
				return false;
			if (! x.KeyHandle.Equals(y.KeyHandle))
				return false;
			if (! x.EnrollmentTime.Equals(y.EnrollmentTime))
				return false;
			if (! x.PublicKey.Equals(y.PublicKey))
				return false;
			if (! x.AttestationCert.Equals(y.AttestationCert))
				return false;

			return true;
		}

		public int GetHashCode(SecurityKeyData obj)
		{
			const int prime = 31;
			var result = 1;
			result = prime*result + EnrollmentTime.GetHashCode();
			result = prime*result + KeyHandle.GetHashCode();
			result = prime*result + PublicKey.GetHashCode();
			result = prime*result + AttestationCert.GetHashCode();

			return result;
		}
	}
}