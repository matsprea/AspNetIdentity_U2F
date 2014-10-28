using System;

namespace U2F.Client
{
	public interface IOriginVerifier {
		void ValidateOrigin(String appId, String origin);
	}
}