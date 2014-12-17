using System;
using System.Linq;
using U2F.Codec;
using U2F.Key;
using U2F.Key.Messages;
using U2F.Server;
using U2F.Server.Message;

namespace U2F.Client.Impl
{
	public class U2FClientReferenceImpl : IU2FClient
	{
		private readonly ICrypto _crypto;
		private readonly IOriginVerifier _appIdVerifier;
		private readonly IChannelIdProvider _channelIdProvider;
		private readonly IU2FServer _server;
		private readonly IU2FKey _key;

		public U2FClientReferenceImpl(ICrypto crypto, IOriginVerifier appIdVerifier,
			IChannelIdProvider channelIdProvider, IU2FServer server, IU2FKey key)
		{
			_crypto = crypto;
			_appIdVerifier = appIdVerifier;
			_channelIdProvider = channelIdProvider;
			_server = server;
			_key = key;
		}

		public void Register(String origin, String accountName)
		{
			var registrationRequest = _server.GetRegistrationRequest(accountName, origin);

			var version = registrationRequest.Version;
			var serverChallengeBase64 = registrationRequest.Challenge;
			var appId = registrationRequest.AppId;
			var sessionId = registrationRequest.SessionId;

			if (!version.Equals(U2FConsts.U2F_V2))
			{
				throw new U2FException(String.Format("Unsupported protocol version: {0}", version));
			}

			_appIdVerifier.ValidateOrigin(appId, origin);

			var channelIdJson = _channelIdProvider.GetJsonChannelId();

			var clientData = ClientDataCodec.EncodeClientData(ClientDataCodec.REQUEST_TYPE_REGISTER, serverChallengeBase64,
				origin, channelIdJson);

			var appIdSha256 = _crypto.ComputeSha256(appId);
			var clientDataSha256 = _crypto.ComputeSha256(clientData);

			var registerResponse = _key.Register(new RegisterRequest(appIdSha256, clientDataSha256));

			var rawRegisterResponse = RawMessageCodec.EncodeRegisterResponse(registerResponse);
			var rawRegisterResponseBase64 = rawRegisterResponse.Base64Urlencode();
			var clientDataBase64 = clientData.GetBytes().Base64Urlencode();

			var milliseconds = Convert.ToInt64((DateTime.Now - new DateTime(1979, 1, 1)).TotalMilliseconds);

			_server.ProcessRegistrationResponse(
				new RegistrationResponse(rawRegisterResponseBase64, clientDataBase64, sessionId), milliseconds);
		}



		public void Authenticate(String origin, String accountName)
		{

			// the key can be used to sign any of the requests - we're gonna sign the first one.
			var signRequest = _server.GetSignRequest(accountName, origin).First();

			var version = signRequest.Version;
			var appId = signRequest.AppId;
			var serverChallengeBase64 = signRequest.Challenge;
			var keyHandleBase64 = signRequest.KeyHandle;
			var sessionId = signRequest.SessionId;

			if (!version.Equals(U2FConsts.U2F_V2))
			{
				throw new U2FException(String.Format("Unsupported protocol version: {0}", version));
			}

			_appIdVerifier.ValidateOrigin(appId, origin);

			var channelIdJson = _channelIdProvider.GetJsonChannelId();

			var clientData = ClientDataCodec.EncodeClientData(ClientDataCodec.REQUEST_TYPE_AUTHENTICATE, serverChallengeBase64,
				origin, channelIdJson);

			var clientDataSha256 = _crypto.ComputeSha256(clientData);
			var appIdSha256 = _crypto.ComputeSha256(appId);
			var keyHandle = keyHandleBase64.Base64Urldecode();

			var authenticateResponse =
				_key.Authenticate(new AuthenticateRequest(UserPresenceVerifier.USER_PRESENT_FLAG, clientDataSha256, appIdSha256,
					keyHandle));

			var rawAuthenticateResponse = RawMessageCodec.EncodeAuthenticateResponse(authenticateResponse);
			var rawAuthenticateResponse64 = rawAuthenticateResponse.Base64Urlencode();
			var clientDataBase64 = clientData.GetBytes().Base64Urlencode();
			var keyHandleDataBase64 = keyHandle.Base64Urlencode();

			_server.ProcessSignResponse(new SignResponse(clientDataBase64, rawAuthenticateResponse64, serverChallengeBase64,
				sessionId, appId, keyHandleDataBase64));
		}
	}
}