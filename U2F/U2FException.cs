using System;

namespace U2F
{
	[Serializable]
	public class U2FException : Exception
	{
		//
		// For guidelines regarding the creation of new exception types, see
		//    http://msdn.microsoft.com/library/default.asp?url=/library/en-us/cpgenref/html/cpconerrorraisinghandlingguidelines.asp
		// and
		//    http://msdn.microsoft.com/library/default.asp?url=/library/en-us/dncscol/html/csharp07192001.asp
		//
		public U2FException(string message) : base(message)
		{
		}

		public U2FException(string message, Exception inner) : base(message, inner)
		{
		}
	}
}