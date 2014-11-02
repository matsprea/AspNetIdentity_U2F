using System;

namespace U2F.Server.Impl
{
	public class SessionIdGenerator : ISessionIdGenerator
	{
		public string GenerateSessionId(string accountName)
		{
			var generateSessionId = accountName + Guid.NewGuid();
			return generateSessionId.GetBytes().Base64Urlencode();
		}
	}
}
