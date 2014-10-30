using System;

namespace U2F.Server.Impl
{
	public class SessionIdGenerator : ISessionIdGenerator
	{
		public string GenerateSessionId(string accountName)
		{
			return Guid.NewGuid().ToString();
		}
	}
}
