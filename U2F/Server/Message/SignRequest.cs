using System;
using System.Collections.Generic;

namespace U2F.Server.Message
{
	public class SignRequest : IEqualityComparer<SignRequest>
	{
		/**
   * Version of the protocol that the to-be-registered U2F token must speak. For
   * the version of the protocol described herein, must be "U2F_V2"
   */
		public String Version { get; private set; }

		/** The websafe-base64-encoded challenge. */
		public String Challenge { get; private set; }

		/**
   * The application id that the RP would like to assert. The U2F token will
   * enforce that the key handle provided above is associated with this
   * application id. The browser enforces that the calling origin belongs to the
   * application identified by the application id.
   */
		public String AppId { get; private set; }

		/**
   * websafe-base64 encoding of the key handle obtained from the U2F token
   * during registration.
   */
		public String KeyHandle { get; private set; }

		/**
   * A session id created by the RP. The RP can opaquely store things like
   * expiration times for the sign-in session, protocol version used, public key
   * expected to sign the identity assertion, etc. The response from the API
   * will include the sessionId. This allows the RP to fire off multiple signing
   * requests, and associate the responses with the correct request
   */
		public String SessionId { get; private set; }

		public SignRequest(String version, String challenge, String appId, String keyHandle,
			String sessionId)
		{

			Version = version;
			Challenge = challenge;
			AppId = appId;
			KeyHandle = keyHandle;
			SessionId = sessionId;
		}


		public bool Equals(SignRequest x, SignRequest y)
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
			if (x.Challenge == null)
			{
				if (y.Challenge != null)
					return false;
			}
			else if (!x.Challenge.Equals(y.Challenge))
				return false;
			if (x.KeyHandle == null)
			{
				if (y.KeyHandle != null)
					return false;
			}
			else if (!x.KeyHandle.Equals(y.KeyHandle))
				return false;
			if (x.SessionId == null)
			{
				if (y.SessionId != null)
					return false;
			}
			else if (!x.SessionId.Equals(y.SessionId))
				return false;
			if (x.Version == null)
			{
				if (y.Version != null)
					return false;
			}
			else if (!x.Version.Equals(y.Version))
				return false;
			return true;
		}

		public int GetHashCode(SignRequest obj)
		{
			const int prime = 31;
			var result = 1;
			result = prime*result + ((AppId == null) ? 0 : AppId.GetHashCode());
			result = prime*result + ((Challenge == null) ? 0 : Challenge.GetHashCode());
			result = prime*result + ((KeyHandle == null) ? 0 : KeyHandle.GetHashCode());
			result = prime*result + ((SessionId == null) ? 0 : SessionId.GetHashCode());
			result = prime*result + ((Version == null) ? 0 : Version.GetHashCode());
			return result;
		}
	}
}