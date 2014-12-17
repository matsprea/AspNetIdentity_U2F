using AspNetIdentity_U2F.Models;
using Microsoft.Owin;
using System.Collections.Generic;
using System.Data.Entity;
using System.Data.Entity.ModelConfiguration.Conventions;
using System.Linq;
using System.Security.Cryptography.X509Certificates;
using U2F.Server;
using U2F.Server.Data;

namespace AspNetIdentity_U2F.DAL
{
	public class U2FDbContext : DbContext, IDataStore
	{

		private readonly ISessionIdGenerator _sessionIdGenerator;

		public U2FDbContext(ISessionIdGenerator sessionIdGenerator)
			: base("U2FConnection")
		{
			_sessionIdGenerator = sessionIdGenerator;
			Database.SetInitializer(new U2FDbInitializer());
		}

		public static U2FDbContext Create(ISessionIdGenerator sessionIdGenerator)
		{
			return new U2FDbContext(sessionIdGenerator);
		}

		public static U2FDbContext Create(IOwinContext context)
		{
			return new U2FDbContext(context.Get<ISessionIdGenerator>("U2F"));
		}

		public DbSet<X509CertificateDb> X509Certificates { get; set; }
		public DbSet<EnrollSessionDataDb> EnrollSessionDatas { get; set; }
		public DbSet<SecurityKeyDataDb> SecurityKeyDatas { get; set; }

		protected override void OnModelCreating(DbModelBuilder modelBuilder)
		{
			modelBuilder.Conventions.Remove<PluralizingTableNameConvention>();
		}

		public void AddTrustedCertificate(X509Certificate2 certificate)
		{
			var x = new X509CertificateDb {RealData = certificate};

			X509Certificates.Add(x);
			SaveChanges();
		}

		public IList<X509Certificate2> GetTrustedCertificates()
		{
			return X509Certificates.ToList().Select(x => x.RealData).ToList();
		}

		public string StoreSessionData(EnrollSessionData sessionData)
		{
			var sessionId = _sessionIdGenerator.GenerateSessionId(sessionData.AccountName);

			var esd = new EnrollSessionDataDb
			{
				SessionId = sessionId,
				RealData = sessionData
			};

			EnrollSessionDatas.Add(esd);
			SaveChanges();

			return sessionId;
		}

		public SignSessionData GetSignSessionData(string sessionId)
		{
			var result = GetEnrollSessionData(sessionId);

			return new SignSessionData(result.AccountName, result.AppId, result.Challenge, null);
		}

		public EnrollSessionData GetEnrollSessionData(string sessionId)
		{
			var result = EnrollSessionDatas.FirstOrDefault(sd => sd.SessionId == sessionId);

			return result != null ? result.RealData : null;
		}

		public void AddSecurityKeyData(string accountName, SecurityKeyData securityKeyData)
		{
			var skd = new SecurityKeyDataDb
			{
				AccountName = accountName,
				RealData = securityKeyData
			};

			SecurityKeyDatas.Add(skd);
			SaveChanges();
		}

		public List<SecurityKeyData> GetSecurityKeyData(string accountName)
		{
			var result = SecurityKeyDatas.Where(sk => sk.AccountName == accountName).ToList();

			return result.Select(skd => skd.RealData).ToList();
		}

		public void RemoveSecuityKey(string accountName, byte[] publicKey)
		{
			var toRemove = SecurityKeyDatas
				.Where(sk => sk.AccountName == accountName)
				.ToList()
				.Where(sk => sk.RealData.PublicKey.SequenceEqual(publicKey));

			SecurityKeyDatas.RemoveRange(toRemove);

			SaveChanges();
		}

		public void UpdateSecurityKeyCounter(string accountName, byte[] publicKey, int newCounterValue)
		{
			var toUpdate = SecurityKeyDatas
				.Where(sk => sk.AccountName == accountName)
				.ToList()
				.Where(sk => sk.RealData.PublicKey.SequenceEqual(publicKey));

			foreach (var sk in toUpdate)
			{
				sk.RealData.Counter = newCounterValue;
			}
			SaveChanges();
		}
	}

	public class U2FDbInitializer : DropCreateDatabaseIfModelChanges<U2FDbContext>
	{
	}

}