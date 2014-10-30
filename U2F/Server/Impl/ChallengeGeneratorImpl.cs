using System;
using Org.BouncyCastle.Security;

namespace U2F.Server.Impl
{
	public class ChallengeGeneratorImpl : IChallengeGenerator
	{
		private const int CHALLENGE_LENGTH = 16;

		private readonly SecureRandom _random = new SecureRandom();

		public byte[] GenerateChallenge(String accountName)
		{
			var result = new byte[CHALLENGE_LENGTH];
			_random.NextBytes(result);
			return result;
		}
	}
}
