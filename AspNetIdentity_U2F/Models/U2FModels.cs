using System;
using System.ComponentModel.DataAnnotations;
using System.ComponentModel.DataAnnotations.Schema;
using System.Security.Cryptography.X509Certificates;
using Newtonsoft.Json;
using U2F.Server.Data;

namespace AspNetIdentity_U2F.Models
{
	public class DbStore<T> where T : class
	{
		public string Data { get; set; }

		[Key]
		public long Id { get; set; }

		[NotMapped]
		public T RealData
		{
			get
			{
				if (string.IsNullOrEmpty(Data))
					return default(T);

				var metaData = JsonConvert.DeserializeObject<T>(Data);

				return metaData;
			}
			set { Data = JsonConvert.SerializeObject(value); }
		}
	}

	public class X509CertificateDb : DbStore<X509Certificate2>
	{
	}

	public class EnrollSessionDataDb : DbStore<EnrollSessionData>
	{
		public String SessionId { get; set; }
	}

	public class SecurityKeyDataDb : DbStore<SecurityKeyData>
	{
		public String AccountName { get; set; }
	}

}