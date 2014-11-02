using System;
using System.IO;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using U2F.Key.Messages;

namespace U2F.Codec
{
	public class RawMessageCodec
	{
		public const byte REGISTRATION_RESERVED_BYTE_VALUE = 0x05;
		public const byte REGISTRATION_SIGNED_RESERVED_BYTE_VALUE = 0x00;

		public static byte[] EncodeRegisterRequest(RegisterRequest registerRequest)
		{
			var appIdSha256 = registerRequest.ApplicationSha256;
			var challengeSha256 = registerRequest.ChallengeSha256;

			var capacity = appIdSha256.Length + challengeSha256.Length;

			var stream = new MemoryStream(capacity);
			using (var writer = new BinaryWriter(stream))
			{
				writer.Write(challengeSha256);
				writer.Write(appIdSha256);
			}
			var result = stream.ToArray();

			return result;
		}

		public static RegisterRequest DecodeRegisterRequest(byte[] data)
		{
			try
			{
				using (var inputStream = new BinaryReader(new MemoryStream(data)))
				{
					var challengeSha256 = inputStream.ReadBytes(32);
					var appIdSha256 = inputStream.ReadBytes(32);

					if (inputStream.BaseStream.Position != inputStream.BaseStream.Length)
					{
						throw new U2FException("Message ends with unexpected data");
					}

					return new RegisterRequest(appIdSha256, challengeSha256);
				}
			}
			catch (IOException e)
			{
				throw new U2FException("Error when parsing raw RegistrationResponse", e);
			}
		}

		public static byte[] EncodeRegisterResponse(RegisterResponse registerResponse)
		{
			var userPublicKey = registerResponse.UserPublicKey;
			var keyHandle = registerResponse.KeyHandle;
			var attestationCertificate = registerResponse.AttestationCertificate;
			var signature = registerResponse.Signature;

			byte[] attestationCertificateBytes;
			try
			{
				attestationCertificateBytes = attestationCertificate.Export(X509ContentType.Cert);
			}
			catch (Exception e)
			{
				throw new U2FException("Error when encoding attestation certificate.", e);
			}

			if (keyHandle.Length > 255)
			{
				throw new U2FException("keyHandle length cannot be longer than 255 bytes!");
			}

			var capacity = 1 + userPublicKey.Length + 1 + keyHandle.Length
			               + attestationCertificateBytes.Length + signature.Length;

			var stream = new MemoryStream(capacity);
			using (var writer = new BinaryWriter(stream))
			{
				writer.Write(REGISTRATION_RESERVED_BYTE_VALUE);
				writer.Write(userPublicKey);
				writer.Write((byte) keyHandle.Length);
				writer.Write(keyHandle);
				//Cam
				writer.Write(attestationCertificateBytes);
				writer.Write(signature);
			}
			var result = stream.ToArray();

			return result;
		}

		public static RegisterResponse DecodeRegisterResponse(byte[] data)
		{
			try
			{
				using (var inputStream = new BinaryReader(new MemoryStream(data)))
				{
					var reservedByte = inputStream.ReadByte();
					var userPublicKey = inputStream.ReadBytes(65);
					var keyHandleSize = inputStream.ReadByte();
					var keyHandle = inputStream.ReadBytes(keyHandleSize);

					var certificatePosition = inputStream.BaseStream.Position;
					var size = (int)(inputStream.BaseStream.Length - inputStream.BaseStream.Position);					
					var bytes = inputStream.ReadBytes(size);
					var attestationCertificate = new X509Certificate(bytes);
					
					inputStream.BaseStream.Position = certificatePosition + attestationCertificate.Export(X509ContentType.Cert).Length;
					size = (int)(inputStream.BaseStream.Length - inputStream.BaseStream.Position);
				
					var signature = inputStream.ReadBytes(size);

					if (reservedByte != REGISTRATION_RESERVED_BYTE_VALUE)
					{
						throw new U2FException(String.Format(
							"Incorrect value of reserved byte. Expected: {0:d}. Was: {1:Dd}",
							REGISTRATION_RESERVED_BYTE_VALUE, reservedByte));
					}

					return new RegisterResponse(userPublicKey, keyHandle, attestationCertificate, signature);
				}
			}
			catch (IOException e)
			{
				throw new U2FException("Error when parsing raw RegistrationResponse", e);
			}
			catch (CryptographicException e)
			{
				throw new U2FException("Error when parsing attestation certificate", e);
			}
		}

		public static byte[] EncodeAuthenticateRequest(AuthenticateRequest authenticateRequest)
		{
			var controlByte = authenticateRequest.Control;
			var appIdSha256 = authenticateRequest.ApplicationSha256;
			var challengeSha256 = authenticateRequest.ChallengeSha256;
			var keyHandle = authenticateRequest.KeyHandle;

			if (keyHandle.Length > 255)
			{
				throw new U2FException("keyHandle length cannot be longer than 255 bytes!");
			}

			var capacity = 1 + appIdSha256.Length + challengeSha256.Length + 1 + keyHandle.Length;

			var stream = new MemoryStream(capacity);
			using (var writer = new BinaryWriter(stream))
			{
				writer.Write(controlByte);
				writer.Write(challengeSha256);
				writer.Write(appIdSha256);
				writer.Write((byte) keyHandle.Length);
				writer.Write(keyHandle);
			}
			var result = stream.ToArray();

			return result;
		}

		public static AuthenticateRequest DecodeAuthenticateRequest(byte[] data)
		{
			try
			{
				using (var inputStream = new BinaryReader(new MemoryStream(data)))
				{
					var controlByte = inputStream.ReadByte();
					var challengeSha256 = inputStream.ReadBytes(32);
					var appIdSha256 = inputStream.ReadBytes(32);

					var size = (int) (inputStream.BaseStream.Length - inputStream.BaseStream.Position);

					if (size > 255)
						throw new U2FException("Message ends with unexpected data");

					var keyHandle = inputStream.ReadBytes(size);

					return new AuthenticateRequest(controlByte, challengeSha256, appIdSha256, keyHandle);
				}
			}
			catch (IOException e)
			{
				throw new U2FException("Error when parsing raw RegistrationResponse", e);
			}
		}

		public static byte[] EncodeAuthenticateResponse(AuthenticateResponse authenticateResponse)
		{
			var userPresence = authenticateResponse.UserPresence;
			var counter = authenticateResponse.Counter;
			var signature = authenticateResponse.Signature;

			var capacity = 1 + 4 + signature.Length;

			var stream = new MemoryStream(capacity);
			using (var writer = new BinaryWriter(stream))
			{
				writer.Write(userPresence);
				writer.Write(counter);
				writer.Write(signature);
			}
			var result = stream.ToArray();

			return result;
		}

		public static AuthenticateResponse DecodeAuthenticateResponse(byte[] data)
		{
			try
			{
				using (var inputStream = new BinaryReader(new MemoryStream(data)))
				{
					var userPresence = inputStream.ReadByte();
					var counter = inputStream.ReadInt32();

					var size = inputStream.BaseStream.Length - inputStream.BaseStream.Position;
					var signature = inputStream.ReadBytes((int) size);

					return new AuthenticateResponse(userPresence, counter, signature);
				}
			}
			catch (IOException e)
			{
				throw new U2FException("Error when parsing rawSignData", e);
			}
		}

		public static byte[] EncodeRegistrationSignedBytes(byte[] applicationSha256, byte[] challengeSha256, byte[] keyHandle, byte[] userPublicKey)
		{
			var capacity = 1 + applicationSha256.Length + challengeSha256.Length + keyHandle.Length + userPublicKey.Length;

			var stream = new MemoryStream(capacity);
			using (var writer = new BinaryWriter(stream))
			{
				writer.Write(REGISTRATION_SIGNED_RESERVED_BYTE_VALUE);
				writer.Write(applicationSha256);
				writer.Write(challengeSha256);
				writer.Write(keyHandle);
				writer.Write(userPublicKey);
			}
			var result = stream.ToArray();

			return result;
		}

		public static byte[] EncodeAuthenticateSignedBytes(byte[] applicationSha256, byte userPresence, int counter, byte[] challengeSha256)
		{
			var capacity = applicationSha256.Length + 1 + 4 + challengeSha256.Length;

			var stream = new MemoryStream(capacity);
			using (var writer = new BinaryWriter(stream))
			{
				writer.Write(applicationSha256);
				writer.Write(userPresence);
				writer.Write(counter);
				writer.Write(challengeSha256);

			}
			var result = stream.ToArray();

			return result;

		}
	}
}
