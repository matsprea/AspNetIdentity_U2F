using System;
using System.Collections.Generic;

namespace U2F.Server.Message
{
	public class RegistrationResponse : IEqualityComparer<RegistrationResponse>
	{
		/** websafe-base64(raw registration response message) */
		public String RegistrationData { get; private set; }

		/** websafe-base64(UTF8(stringified(client data))) */
		public String Bd { get; private set; }

		/** session id originally passed */
		public String SessionId { get; private set; }

		public RegistrationResponse(String registrationData, String bd, String sessionId)
		{
			RegistrationData = registrationData;
			Bd = bd;
			SessionId = sessionId;
		}

		public bool Equals(RegistrationResponse x, RegistrationResponse y)
		{
			if (x == y)
				return true;
			if (y == null)
				return false;

			if (x.Bd == null)
			{
				if (y.Bd != null)
					return false;
			}
			else if (!x.Bd.Equals(y.Bd))
				return false;
			if (x.RegistrationData == null)
			{
				if (y.RegistrationData != null)
					return false;
			}
			else if (!x.RegistrationData.Equals(y.RegistrationData))
				return false;
			if (x.SessionId == null)
			{
				if (y.SessionId != null)
					return false;
			}
			else if (!x.SessionId.Equals(y.SessionId))
				return false;
			return true;
		}

		public int GetHashCode(RegistrationResponse obj)
		{
			const int prime = 31;
			var result = 1;
			result = prime*result + ((Bd == null) ? 0 : Bd.GetHashCode());
			result = prime*result + ((RegistrationData == null) ? 0 : RegistrationData.GetHashCode());
			result = prime*result + ((SessionId == null) ? 0 : SessionId.GetHashCode());
			return result;
		}
	}
}