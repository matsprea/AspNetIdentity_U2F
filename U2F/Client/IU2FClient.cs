using System;

namespace U2F.Client
{
	public interface IU2FClient {
		void Register(String origin, String accountName)  ;

		void Authenticate(String origin, String accountName) ;
	}
}