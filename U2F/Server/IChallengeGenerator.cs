using System;

namespace U2F.Server
{
	public interface IChallengeGenerator
	{

		byte[] GenerateChallenge(String accountName);
	}
}