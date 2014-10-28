using System;
using System.IO;
using U2F.Key.Messages;

namespace U2F.Codec
{
	public class SerialCodec
	{
		public const byte VERSION = (byte) 0x02;
		public const byte COMMAND_REGISTER = (byte) 0x01;
		public const byte COMMAND_AUTHENTICATE = (byte) 0x02;

		public static void SendRegisterRequest(Stream outputStream, RegisterRequest registerRequest)
		{
			SendRequest(outputStream, COMMAND_REGISTER, RawMessageCodec.EncodeRegisterRequest(registerRequest));
		}

		public static void SendRegisterResponse(Stream outputStream, RegisterResponse registerResponse)
		{
			SendResponse(outputStream, RawMessageCodec.EncodeRegisterResponse(registerResponse));
		}

		public static void SendAuthenticateRequest(Stream outputStream, AuthenticateRequest authenticateRequest)
		{
			SendRequest(outputStream, COMMAND_AUTHENTICATE,
				RawMessageCodec.EncodeAuthenticateRequest(authenticateRequest));
		}

		public static void SendAuthenticateResponse(Stream outputStream, AuthenticateResponse authenticateResponse)
		{
			SendResponse(outputStream, RawMessageCodec.EncodeAuthenticateResponse(authenticateResponse));
		}

		private static void SendRequest(Stream outputStream, byte command, byte[] encodedBytes)
		{
			if (encodedBytes.Length > 65535)
			{
				throw new U2FException("Message is too long to be transmitted over this protocol");
			}

			using (var writer = new BinaryWriter(outputStream))
			{
				writer.Write(VERSION);
				writer.Write(command);
				writer.Write(encodedBytes.Length);
				writer.Write(encodedBytes);

				writer.Flush();
			}
		}

		private static void SendResponse(Stream outputStream, byte[] encodedBytes)
		{
			if (encodedBytes.Length > 65535)
			{
				throw new U2FException("Message is too long to be transmitted over this protocol");
			}

			using (var writer = new BinaryWriter(outputStream))
			{
				writer.Write(encodedBytes.Length);
				writer.Write(encodedBytes);
				writer.Flush();
			}
		}

		public static U2FRequest ParseRequest(Stream inputStream)
		{
			using (var read = new BinaryReader(inputStream))
			{
				var version = read.ReadByte();

				if (version != VERSION)
					throw new U2FException(String.Format("Unsupported message version: {0:d}", version));

				var command = read.ReadByte();
				switch (command)
				{
					case COMMAND_REGISTER:
						return RawMessageCodec.DecodeRegisterRequest(ParseMessage(read));
					case COMMAND_AUTHENTICATE:
						return RawMessageCodec.DecodeAuthenticateRequest(ParseMessage(read));
					default:
						throw new U2FException(String.Format("Unsupported command: {O:d}", command));
				}

			}
		}

		public static RegisterResponse ParseRegisterResponse(Stream inputStream)
		{
			using (var reader = new BinaryReader(inputStream))
			{
				return RawMessageCodec.DecodeRegisterResponse(ParseMessage(reader));
			}
		}

		public static AuthenticateResponse ParseAuthenticateResponse(Stream inputStream)
		{
			using (var reader = new BinaryReader(inputStream))
			{
				return RawMessageCodec.DecodeAuthenticateResponse(ParseMessage(reader));
			}
		}

		private static byte[] ParseMessage(BinaryReader dataInputStream)
		{
			var size = (int) (dataInputStream.BaseStream.Length - dataInputStream.BaseStream.Position);
			var result = dataInputStream.ReadBytes(size);

			return result;
		}
	}
}
