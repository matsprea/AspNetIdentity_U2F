using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using U2F.Codec;
using U2F.Key.Messages;

namespace U2F.Key
{
	public class U2FKeyReferenceImpl : IU2FKey
	{
		//private static final Logger Log = Logger.getLogger(U2FKeyReferenceImpl.class.getName());

		private readonly X509Certificate2 _vendorCertificate;
		private readonly CngKey _certificatePrivateKey;
		private readonly IKeyPairGenerator _keyPairGenerator;
		private readonly IKeyHandleGenerator _keyHandleGenerator;
		private readonly IDataStore _dataStore;
		private readonly UserPresenceVerifier _userPresenceVerifier;
		private readonly ICrypto _crypto;

		public U2FKeyReferenceImpl(X509Certificate2 vendorCertificate, CngKey certificatePrivateKey,
			IKeyPairGenerator keyPairGenerator, IKeyHandleGenerator keyHandleGenerator,
			IDataStore dataStore, UserPresenceVerifier userPresenceVerifier, ICrypto crypto)
		{
			_vendorCertificate = vendorCertificate;
			_certificatePrivateKey = certificatePrivateKey;
			_keyPairGenerator = keyPairGenerator;
			_keyHandleGenerator = keyHandleGenerator;
			_dataStore = dataStore;
			_userPresenceVerifier = userPresenceVerifier;
			_crypto = crypto;
		}


		public RegisterResponse Register(RegisterRequest registerRequest)
		{
			//Log.info(">> register");

			var applicationSha256 = registerRequest.ApplicationSha256;
			var challengeSha256 = registerRequest.ChallengeSha256;

			//Log.info(" -- Inputs --");
			//Log.info("  applicationSha256: " + applicationSha256.ToHex());
			//Log.info("  challengeSha256: " + challengeSha256.ToHex()));

			var userPresent = _userPresenceVerifier.VerifyUserPresence();
			if ((userPresent & UserPresenceVerifier.USER_PRESENT_FLAG) == 0)
			{
				throw new U2FException("Cannot verify user presence");
			}

			var keyPair = _keyPairGenerator.GenerateKeyPair(applicationSha256, challengeSha256);
			var keyHandle = _keyHandleGenerator.GenerateKeyHandle(applicationSha256, keyPair);

			_dataStore.StoreKeyPair(keyHandle, keyPair);

			var userPublicKey = _keyPairGenerator.EncodePublicKey(keyPair.PublicKey);

			var signedData = RawMessageCodec.EncodeRegistrationSignedBytes(applicationSha256, challengeSha256, keyHandle, userPublicKey);
			//Log.info("Signing bytes " + Hex.encodeHexString(signedData));

			var signature = _crypto.Sign(signedData, _certificatePrivateKey);

			//Log.info(" -- Outputs --");
			//Log.info("  userPublicKey: " + Hex.encodeHexString(userPublicKey));
			//Log.info("  keyHandle: " + Hex.encodeHexString(keyHandle));
			//Log.info("  vendorCertificate: " + vendorCertificate);
			//Log.info("  signature: " + Hex.encodeHexString(signature));

			//Log.info("<< register");

			return new RegisterResponse(userPublicKey, keyHandle, _vendorCertificate, signature);
		}

		public AuthenticateResponse Authenticate(AuthenticateRequest authenticateRequest)
		{
			//Log.info(">> authenticate");

			var control = authenticateRequest.Control;
			var applicationSha256 = authenticateRequest.ApplicationSha256;
			var challengeSha256 = authenticateRequest.ChallengeSha256;
			var keyHandle = authenticateRequest.KeyHandle;

			// Log.info(" -- Inputs --");
			//Log.info("  control: " + control);
			//Log.info("  applicationSha256: " + Hex.encodeHexString(applicationSha256));
			//Log.info("  challengeSha256: " + Hex.encodeHexString(challengeSha256));
			//Log.info("  keyHandle: " + Hex.encodeHexString(keyHandle));

			var keyPair = _dataStore.GetKeyPair(keyHandle);
			var counter = _dataStore.IncrementCounter();
			var userPresence = _userPresenceVerifier.VerifyUserPresence();
			var signedData = RawMessageCodec.EncodeAuthenticateSignedBytes(applicationSha256, userPresence, counter,
				challengeSha256);

			//Log.info("Signing bytes " + Hex.encodeHexString(signedData));

			var signature = _crypto.Sign(signedData, keyPair.PrivateKey);

			//Log.info(" -- Outputs --");
			//Log.info("  userPresence: " + userPresence);
			//Log.info("  counter: " + counter);
			//Log.info("  signature: " + Hex.encodeHexString(signature));

			//Log.info("<< authenticate");

			return new AuthenticateResponse(userPresence, counter, signature);
		}
	}
}