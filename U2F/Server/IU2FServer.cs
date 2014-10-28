using System;
using System.Collections.Generic;
using U2F.Server.Data;
using U2F.Server.Message;

namespace U2F.Server
{
	public interface IU2FServer
	{

		// registration //
		RegistrationRequest GetRegistrationRequest(String accountName, String appId);

		SecurityKeyData ProcessRegistrationResponse(RegistrationResponse registrationResponse, long currentTimeInMillis);

		// authentication //
		IList<SignRequest> GetSignRequest(String accountName, String appId);

		SecurityKeyData ProcessSignResponse(SignResponse signResponse);

		// token management //
		List<SecurityKeyData> GetAllSecurityKeys(String accountName);

		void RemoveSecurityKey(String accountName, byte[] publicKey);
	}
}