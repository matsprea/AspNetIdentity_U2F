using System;
using Newtonsoft.Json.Linq;

namespace U2F.Codec
{
	public class ClientDataCodec {
		// Constants for ClientData.typ
		public const String REQUEST_TYPE_REGISTER = "navigator.id.finishEnrollment";
		public const String REQUEST_TYPE_AUTHENTICATE = "navigator.id.getAssertion";

		// Constants for building ClientData.challenge
		public const String JSON_PROPERTY_REQUEST_TYPE = "typ";
		public const String JSON_PROPERTY_SERVER_CHALLENGE_BASE64 = "challenge";
		public const String JSON_PROPERTY_SERVER_ORIGIN = "origin";
		public const String JSON_PROPERTY_CHANNEL_ID = "cid_pubkey";

		/** Computes ClientData.challenge */
		public static String EncodeClientData(String requestType, String serverChallengeBase64,
			String origin, JObject jsonChannelId)
		{
			var browserData = new JObject
			{
				{JSON_PROPERTY_REQUEST_TYPE, requestType},
				{JSON_PROPERTY_SERVER_CHALLENGE_BASE64, serverChallengeBase64},
				{JSON_PROPERTY_CHANNEL_ID, jsonChannelId},
				{JSON_PROPERTY_SERVER_ORIGIN, origin}
			};
			return browserData.ToString();
		}
	}
}