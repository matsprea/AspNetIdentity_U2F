using System;

namespace U2F.Server.Data
{
	[Serializable]
	public class EnrollSessionData
	{
		private const long serialVersionUID = 1750990095756334568L;

		public String AccountName { get; private set; }
		public byte[] Challenge { get; private set; }
		public String AppId { get; private set; }

		public EnrollSessionData(String accountName, String appId, byte[] challenge)
		{
			AccountName = accountName;
			Challenge = challenge;
			AppId = appId;
		}
	}
}

