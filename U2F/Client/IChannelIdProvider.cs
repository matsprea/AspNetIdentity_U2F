using Newtonsoft.Json.Linq;

namespace U2F.Client
{
	public interface IChannelIdProvider
	{
		JObject GetJsonChannelId();
	}
}
