using System.Collections.Generic;

namespace U2F.Key.Messages
{
	public class AuthenticateResponse : U2FResponse, IEqualityComparer<AuthenticateResponse>
	{
		/**
		* Bit 0 is set to 1, which means that user presence was verified. (This
		* version of the protocol doesn't specify a way to request authentication
		* responses without requiring user presence.) A different value of Bit 0, as
		* well as Bits 1 through 7, are reserved for future use. The values of Bit 1
		* through 7 SHOULD be 0
		*/
		public byte UserPresence { get; private set; }

		/**
		* This is the big-endian representation of a counter value that the U2F token
		* increments every time it performs an authentication operation.
		*/
		public int Counter { get; private set; }


		/** This is a ECDSA signature (on P-256) */
		public byte[] Signature { get; private set; }

		public AuthenticateResponse(byte userPresence, int counter, byte[] signature)
		{

			UserPresence = userPresence;
			Counter = counter;
			Signature = signature;
		}

		public bool Equals(AuthenticateResponse x, AuthenticateResponse y)
		{
			if (x == y)
				return true;
			if (y == null)
				return false;
			if (x.Counter != y.Counter)
				return false;
			if (!x.Signature.Equals(y.Signature))
				return false;
			if (x.UserPresence != y.UserPresence)
				return false;
			return true;
		}

		public int GetHashCode(AuthenticateResponse obj)
		{
			const int prime = 31;
			var result = 1;
			result = prime*result + Counter;
			result = prime*result + Signature.GetHashCode();
			result = prime*result + UserPresence;
			return result;
		}
	}
}