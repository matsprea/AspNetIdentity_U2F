using System;

namespace U2F.Client
{
	public interface ICrypto {
		byte[] ComputeSha256(String message);
	}
}