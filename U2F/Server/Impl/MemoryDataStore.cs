using System;
using System.Collections.Generic;
using System.Security.Cryptography.X509Certificates;
using U2F.Server.Data;

namespace U2F.Server.Impl
{
	public class MemoryDataStore : IDataStore
	{
		private readonly IList<X509Certificate> _trustedCertificateDataBase = new List<X509Certificate>();
		private readonly Dictionary<string, EnrollSessionData> _sessionDataBase = new Dictionary<string, EnrollSessionData>();
		private readonly Dictionary<string, List<SecurityKeyData>> _securityKeyDataBase = new Dictionary<string, List<SecurityKeyData>>();

		private readonly ISessionIdGenerator _sessionIdGenerator;

		public MemoryDataStore(ISessionIdGenerator sessionIdGenerator)
		{
			this._sessionIdGenerator = sessionIdGenerator;
		}

		public String StoreSessionData(EnrollSessionData sessionData)
		{
			var sessionId = _sessionIdGenerator.GenerateSessionId(sessionData.AccountName);
			_sessionDataBase.Add(sessionId, sessionData);
			return sessionId;
		}

		public EnrollSessionData GetEnrollSessionData(String sessionId)
		{
			return _sessionDataBase[sessionId];
		}

		public SignSessionData GetSignSessionData(String sessionId)
		{
			return (SignSessionData) _sessionDataBase[sessionId];
		}

		public void AddSecurityKeyData(String accountName, SecurityKeyData securityKeyData)
		{
			var tokens = GetSecurityKeyData(accountName);
			tokens.Add(securityKeyData);
			_securityKeyDataBase.Add(accountName, tokens);
		}

		public List<SecurityKeyData> GetSecurityKeyData(String accountName)
		{
			return _securityKeyDataBase[accountName] ?? new List<SecurityKeyData>();
		}

		public IList<X509Certificate> GetTrustedCertificates()
		{
			return _trustedCertificateDataBase;
		}

		public void AddTrustedCertificate(X509Certificate certificate)
		{
			_trustedCertificateDataBase.Add(certificate);
		}

		public void RemoveSecuityKey(String accountName, byte[] publicKey)
		{
			var tokens = GetSecurityKeyData(accountName);
			foreach (var token in tokens)
			{
				if (token.PublicKey.Equals(publicKey))
				{
					tokens.Remove(token);
					break;
				}
			}
		}

		public void UpdateSecurityKeyCounter(String accountName, byte[] publicKey, int newCounterValue)
		{
			var tokens = GetSecurityKeyData(accountName);
			foreach (var token in tokens)
			{
				if (token.PublicKey.Equals(publicKey))
				{
					token.Counter = newCounterValue;
					break;
				}
			}
		}
	}
}