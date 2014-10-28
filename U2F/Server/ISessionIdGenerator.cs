using System;

namespace U2F.Server
{
	public interface ISessionIdGenerator
	{

		String GenerateSessionId(String accountName);
	}
}
