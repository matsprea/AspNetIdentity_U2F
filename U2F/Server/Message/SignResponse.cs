using System;
using System.Collections.Generic;

namespace U2F.Server.Message
{
	public class SignResponse : IEqualityComparer<SignResponse>
	{

		/** websafe-base64(client data) */
		public String Bd { get; private set; }

		/** websafe-base64(raw response from U2F device) */
		public String Sign { get; private set; }

		/** challenge originally passed */
		public String Challenge { get; private set; }

		/** session id originally passed */
		public String SessionId { get; private set; }

		/** application id originally passed */
		public String AppId { get; private set; }

		/** keyHandle to manage multiple keys**/
		public String KeyHandle { get; private set; }

		public SignResponse(String bd, String sign, String challenge, String sessionId, String appId, string keyHandle)
		{
			Bd = bd;
			Sign = sign;
			Challenge = challenge;
			SessionId = sessionId;
			AppId = appId;
			KeyHandle = keyHandle;
		}


		public bool Equals(SignResponse x, SignResponse y)
		{
			if (x == y)
				return true;
			if (y == null)
				return false;

			if (x.AppId == null)
			{
				if (y.AppId != null)
					return false;
			}
			else if (!x.AppId.Equals(y.AppId))
				return false;
			if (x.Bd == null)
			{
				if (y.Bd != null)
					return false;
			}
			else if (!x.Bd.Equals(y.Bd))
				return false;
			if (x.Challenge == null)
			{
				if (y.Challenge != null)
					return false;
			}
			else if (!x.Challenge.Equals(y.Challenge))
				return false;
			if (x.SessionId == null)
			{
				if (y.SessionId != null)
					return false;
			}
			else if (!x.SessionId.Equals(y.SessionId))
				return false;
			if (x.Sign == null)
			{
				if (y.Sign != null)
					return false;
			}
			else if (!x.Sign.Equals(y.Sign))
				return false;
			if (x.KeyHandle == null)
			{
				if (y.KeyHandle != null)
					return false;
			}
			else if (!x.KeyHandle.Equals(y.KeyHandle))
				return false;
			return true;
		}

		public int GetHashCode(SignResponse obj)
		{
			const int prime = 31;
			var result = 1;
			result = prime*result + ((AppId == null) ? 0 : AppId.GetHashCode());
			result = prime*result + ((Bd == null) ? 0 : Bd.GetHashCode());
			result = prime*result + ((Challenge == null) ? 0 : Challenge.GetHashCode());
			result = prime*result + ((SessionId == null) ? 0 : SessionId.GetHashCode());
			result = prime*result + ((Sign == null) ? 0 : Sign.GetHashCode());
			return result;
		}
	}
}