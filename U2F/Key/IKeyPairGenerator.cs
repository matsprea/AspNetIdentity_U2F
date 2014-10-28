using System;
using System.Collections.Generic;
using System.Linq;
using Org.BouncyCastle.Bcpg.OpenPgp;

namespace U2F.Key
{
	public interface IKeyPairGenerator
	{
		PgpKeyPair GenerateKeyPair(byte[] applicationSha256, byte[] challengeSha256);
		byte[] EncodePublicKey(PgpPublicKey publicKey);
	}
}
