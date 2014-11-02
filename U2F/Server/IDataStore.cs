using System;
using System.Collections.Generic;
using System.Security.Cryptography.X509Certificates;
using U2F.Server.Data;

namespace U2F.Server
{
	public interface IDataStore
	{

		// attestation certs and trust
		void AddTrustedCertificate(X509Certificate2 certificate);

		IList<X509Certificate2> GetTrustedCertificates();


		// session handling
		/* sessionId */ String StoreSessionData(EnrollSessionData sessionData);

		SignSessionData GetSignSessionData(String sessionId);

		EnrollSessionData GetEnrollSessionData(String sessionId);

		// security key management
		void AddSecurityKeyData(String accountName, SecurityKeyData securityKeyData);

		List<SecurityKeyData> GetSecurityKeyData(String accountName);

		void RemoveSecuityKey(String accountName, byte[] publicKey);

		void UpdateSecurityKeyCounter(String accountName, byte[] publicKey, int newCounterValue);
	}
}