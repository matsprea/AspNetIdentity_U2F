using Newtonsoft.Json.Linq;
using System;
using System.Collections.Generic;
using System.Linq;
using U2F.Codec;
using U2F.Key;
using U2F.Server.Data;
using U2F.Server.Message;

namespace U2F.Server.Impl
{
	public class U2FServerReferenceImpl : IU2FServer
	{

		private static readonly String TYPE_PARAM = "typ";
		private static readonly String CHALLENGE_PARAM = "challenge";
		private static readonly String ORIGIN_PARAM = "origin";

		// TODO: use these for channel id checks in verifyBrowserData
		private static readonly String CHANNEL_ID_PARAM = "cid_pubkey";
		private static readonly String UNUSED_CHANNEL_ID = "";

		// private static final Logger Log = Logger.getLogger(U2FServerReferenceImpl.class.getName());

		private readonly IChallengeGenerator _challengeGenerator;
		private readonly IDataStore _dataStore;
		private readonly ICrypto _cryto;
		private readonly IList<String> _allowedOrigins;

		public U2FServerReferenceImpl(IChallengeGenerator challengeGenerator, IDataStore dataStore, ICrypto cryto, IEnumerable<string> origins)
		{
			_challengeGenerator = challengeGenerator;
			_dataStore = dataStore;
			_cryto = cryto;
			_allowedOrigins = CanonicalizeOrigins(origins);
		}

		public RegistrationRequest GetRegistrationRequest(String accountName, String appId)
		{
			//Log.info(">> getRegistrationRequest " + accountName);

			var challenge = _challengeGenerator.GenerateChallenge(accountName);
			var sessionData = new EnrollSessionData(accountName, appId, challenge);

			var sessionId = _dataStore.StoreSessionData(sessionData);

			var challengeBase64 = challenge.Base64Urlencode();

			// Log.info("-- Output --");
			//Log.info("  sessionId: " + sessionId);
			//Log.info("  challenge: " + challenge.ToHex());

			//Log.info("<< getRegistrationRequest " + accountName);

			return new RegistrationRequest(U2FConsts.U2F_V2, challengeBase64, appId, sessionId);
		}

		public SecurityKeyData ProcessRegistrationResponse(RegistrationResponse registrationResponse,
			long currentTimeInMillis)
		{
			//Log.info(">> processRegistrationResponse");

			var sessionId = registrationResponse.SessionId;
			var browserDataBase64 = registrationResponse.Bd;
			var rawRegistrationDataBase64 = registrationResponse.RegistrationData;

			var sessionData = _dataStore.GetEnrollSessionData(sessionId);

			if (sessionData == null)
			{
				throw new U2FException("Unknown session_id");
			}

			var appId = sessionData.AppId;
			var browserData = browserDataBase64.Base64Urldecode().GetString();
			var rawRegistrationData = rawRegistrationDataBase64.Base64Urldecode();

			/*
			Log.info("-- Input --");
			Log.info("  sessionId: " + sessionId);
			Log.info("  challenge: " + Hex.encodeHexString(sessionData.GetChallenge()));
			Log.info("  accountName: " + sessionData.GetAccountName());
			Log.info("  browserData: " + browserData);
			Log.info("  rawRegistrationData: " + Hex.encodeHexString(rawRegistrationData));
			*/

			var registerResponse = RawMessageCodec.DecodeRegisterResponse(rawRegistrationData);
			var userPublicKey = registerResponse.UserPublicKey;
			var keyHandle = registerResponse.KeyHandle;
			var attestationCertificate = registerResponse.AttestationCertificate;
			var signature = registerResponse.Signature;

			/*
			Log.info("-- Parsed rawRegistrationResponse --");
			Log.info("  userPublicKey: " + Hex.encodeHexString(userPublicKey));
			Log.info("  keyHandle: " + Hex.encodeHexString(keyHandle));
			Log.info("  attestationCertificate: " + attestationCertificate.toString());
			try
			{
				Log.info("  attestationCertificate bytes: "
				         + Hex.encodeHexString(attestationCertificate.getEncoded()));
			}
			catch (CertificateEncodingException e)
			{
				throw new U2FException("Cannot encode certificate", e);
			}
			Log.info("  signature: " + Hex.encodeHexString(signature));
			*/
			var appIdSha256 = _cryto.ComputeSha256(appId.GetBytes());
			var browserDataSha256 = _cryto.ComputeSha256(browserData.GetBytes());
			var signedBytes = RawMessageCodec.EncodeRegistrationSignedBytes(appIdSha256, browserDataSha256,
				keyHandle, userPublicKey);

			var trustedCertificates = _dataStore.GetTrustedCertificates();
			if (!trustedCertificates.Contains(attestationCertificate))
			{
				//Log.warning("attestion cert is not trusted");
			}

			VerifyBrowserData(browserData, "navigator.id.finishEnrollment", sessionData);

			//Log.info("Verifying signature of bytes " + Hex.encodeHexString(signedBytes));
			if (!_cryto.VerifySignature(attestationCertificate, signedBytes, signature))
			{
				throw new U2FException("Signature is invalid");
			}

			// The first time we create the SecurityKeyData, we set the counter value to 0.
			// We don't actually know what the counter value of the real device is - but it will
			// be something bigger (or equal) to 0, so subsequent signatures will check out ok.
			var securityKeyData = new SecurityKeyData(currentTimeInMillis,
				keyHandle, userPublicKey, attestationCertificate, /* initial counter value */ 0);
			_dataStore.AddSecurityKeyData(sessionData.AccountName, securityKeyData);

			//Log.info("<< processRegistrationResponse");
			return securityKeyData;
		}

		public IList<SignRequest> GetSignRequest(String accountName, String appId)
		{
			//Log.info(">> getSignRequest " + accountName);

			var securityKeyDataList = _dataStore.GetSecurityKeyData(accountName);

			var result = new List<SignRequest>();

			foreach (var securityKeyData in securityKeyDataList)
			{
				var challenge = _challengeGenerator.GenerateChallenge(accountName);

				var sessionData = new SignSessionData(accountName, appId, challenge, securityKeyData.PublicKey);
				var sessionId = _dataStore.StoreSessionData(sessionData);

				var keyHandle = securityKeyData.KeyHandle;
				/*
				Log.info("-- Output --");
				Log.info("  sessionId: " + sessionId);
				Log.info("  challenge: " + Hex.encodeHexString(challenge));
				Log.info("  keyHandle: " + Hex.encodeHexString(keyHandle));
				*/
				var challengeBase64 = challenge.Base64Urlencode();
				var keyHandleBase64 = keyHandle.Base64Urlencode();

				//Log.info("<< getSignRequest " + accountName);
				result.Add(new SignRequest(U2FConsts.U2F_V2, challengeBase64, appId, keyHandleBase64, sessionId));
			}
			return result;
		}

		public SecurityKeyData ProcessSignResponse(SignResponse signResponse)
		{
			//Log.info(">> processSignResponse");

			var sessionId = signResponse.SessionId;
			var browserDataBase64 = signResponse.Bd;
			var rawSignDataBase64 = signResponse.Sign;

			var sessionData = _dataStore.GetSignSessionData(sessionId);

			if (sessionData == null)
			{
				throw new U2FException("Unknown session_id");
			}

			var appId = sessionData.AppId;
			SecurityKeyData securityKeyData = null;

			foreach (var temp in _dataStore.GetSecurityKeyData(sessionData.AccountName))
			{
				if (sessionData.PublicKey.SequenceEqual(temp.PublicKey))
				{
					securityKeyData = temp;
					break;
				}
			}

			if (securityKeyData == null)
			{
				throw new U2FException("No security keys registered for this user");
			}

			var browserData = browserDataBase64.Base64Urldecode().GetString();
			var rawSignData = rawSignDataBase64.Base64Urldecode();

			//Log.info("-- Input --");
			//Log.info("  sessionId: " + sessionId);
			//Log.info("  publicKey: " + Hex.encodeHexString(securityKeyData.GetPublicKey()));
			//Log.info("  challenge: " + Hex.encodeHexString(sessionData.GetChallenge()));
			//Log.info("  accountName: " + sessionData.GetAccountName());
			//Log.info("  browserData: " + browserData);
			//Log.info("  rawSignData: " + Hex.encodeHexString(rawSignData));

			VerifyBrowserData(browserData, "navigator.id.getAssertion", sessionData);

			var authenticateResponse = RawMessageCodec.DecodeAuthenticateResponse(rawSignData);
			var userPresence = authenticateResponse.UserPresence;
			var counter = authenticateResponse.Counter;
			var signature = authenticateResponse.Signature;

			//Log.info("-- Parsed rawSignData --");
			//Log.info("  userPresence: " + Integer.toHexString(userPresence & 0xFF));
			//Log.info("  counter: " + counter);
			//Log.info("  signature: " + Hex.encodeHexString(signature));

			if (userPresence != UserPresenceVerifier.USER_PRESENT_FLAG)
			{
				throw new U2FException("User presence invalid during authentication");
			}

			if (counter <= securityKeyData.Counter)
			{
				throw new U2FException("Counter value smaller than expected!");
			}

			var appIdSha256 = _cryto.ComputeSha256(appId.GetBytes());
			var browserDataSha256 = _cryto.ComputeSha256(browserData.GetBytes());
			var signedBytes = RawMessageCodec.EncodeAuthenticateSignedBytes(appIdSha256, userPresence,
				counter, browserDataSha256);

			//Log.info("Verifying signature of bytes " + Hex.encodeHexString(signedBytes));
			if (!_cryto.VerifySignature(_cryto.DecodePublicKey(securityKeyData.PublicKey), signedBytes,
				signature))
			{
				throw new U2FException("Signature is invalid");
			}

			_dataStore.UpdateSecurityKeyCounter(sessionData.AccountName, securityKeyData.PublicKey, counter);

			//Log.info("<< processSignResponse");
			return securityKeyData;
		}

		private void VerifyBrowserData(string browserDataAsElement, String messageType, EnrollSessionData sessionData)
		{
			JObject browserData;
			try
			{
				browserData = JObject.Parse(browserDataAsElement);
			}
			catch (Exception e)
			{
				throw new U2FException("browserdata has wrong format", e);
			}

			// check that the right "typ" parameter is present in the browserdata JSON
			if (browserData.Property(TYPE_PARAM) == null)
			{
				throw new U2FException("bad browserdata: missing 'typ' param");
			}

			var type = browserData.Property(TYPE_PARAM).Value.ToString();
			if (messageType != type)
			{
				throw new U2FException("bad browserdata: bad type " + type);
			}

			// check that the right challenge is in the browserdata
			if (browserData.Property(CHALLENGE_PARAM) == null)
			{
				throw new U2FException("bad browserdata: missing 'challenge' param");
			}

			if (browserData.Property(ORIGIN_PARAM) == null)
			{
				VerifyOrigin(browserData.Property(ORIGIN_PARAM).Value.ToString());
			}

			var challengeFromBrowserData = browserData.Property(CHALLENGE_PARAM).Value.ToString().Base64Urldecode();


			if (!challengeFromBrowserData.SequenceEqual(sessionData.Challenge))
			{
				throw new U2FException("wrong challenge signed in browserdata");
			}

			// TODO: Deal with ChannelID
		}

		private void VerifyOrigin(String origin)
		{
			if (!_allowedOrigins.Contains(CanonicalizeOrigin(origin)))
			{
				throw new U2FException(origin + " is not a recognized home origin for this backend");
			}
		}

		public List<SecurityKeyData> GetAllSecurityKeys(String accountName)
		{
			return _dataStore.GetSecurityKeyData(accountName);
		}


		public void RemoveSecurityKey(String accountName, byte[] publicKey)
		{
			_dataStore.RemoveSecuityKey(accountName, publicKey);
		}

		private static IList<String> CanonicalizeOrigins(IEnumerable<string> origins)
		{
			return origins.Select(CanonicalizeOrigin).ToList();
		}

		private static String CanonicalizeOrigin(String url)
		{
			Uri uri;
			try
			{
				uri = new Uri(url);
			}
			catch (Exception e)
			{
				throw new U2FException("specified bad origin", e);
			}
			return uri.Scheme + "://" + uri.Host + ":" + uri.Port;
		}
	}
}
