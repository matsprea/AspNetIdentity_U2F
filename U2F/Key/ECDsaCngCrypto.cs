using System;
using System.Security.Cryptography;

namespace U2F.Key
{
	public class ECDsaCngCrypto : ICrypto
	{
		public byte[] Sign(byte[] signedData, CngKey privateKey)
		{
			try
			{
				var ecDsaCng = new ECDsaCng(privateKey)
				{
					HashAlgorithm = CngAlgorithm.Sha256
				};

				return ecDsaCng.SignData(signedData);

			}
			catch (ArgumentNullException e)
			{
				throw new U2FException("Error when signing", e);
			}
			catch (CryptographicException e)
			{
				throw new U2FException("Error when signing", e);
			}
		}
	}
}