using System;
using System.Security.Cryptography;

namespace U2F.Client.Impl
{
	public class CryptoImpl : ICrypto
	{
		public byte[] ComputeSha256(String message)
		{
			try
			{
				var mySHA256 = SHA256Cng.Create();
				var hash = mySHA256.ComputeHash(message.GetBytes());
				return hash;
			}
			catch (Exception e)
			{
				throw new U2FException("Cannot compute SHA-256", e);
			}
		}
	}
}
