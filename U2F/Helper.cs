using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;

namespace U2F
{
	public static class Helper
	{
		private static readonly string[] HexTbl = Enumerable.Range(0, 256).Select(v => v.ToString("X2")).ToArray();

		public static string ToHex(this IEnumerable<byte> array)
		{
			var s = new StringBuilder();
			foreach (var v in array)
				s.Append(HexTbl[v]);
			return s.ToString();
		}

		public static string ToHex(this byte[] array)
		{
			var s = new StringBuilder(array.Length*2);
			foreach (var v in array)
				s.Append(HexTbl[v]);
			return s.ToString();
		}

		public static byte[] FromHex(this string hex)
		{
			return Enumerable.Range(0, hex.Length)
				.Where(x => x%2 == 0)
				.Select(x => Convert.ToByte(hex.Substring(x, 2), 16))
				.ToArray();
		}

		public static string Base64Urlencode(this byte[] arg)
		{
			var s = Convert.ToBase64String(arg); // Regular base64 encoder
			s = s.TrimEnd('='); // Remove any trailing '='s
			s = s.Replace('+', '-'); // 62nd char of encoding
			s = s.Replace('/', '_'); // 63rd char of encoding
			return s;
		}

		public static byte[] Base64Urldecode(this string arg)
		{
			var s = arg;
			s = s.Replace('-', '+'); // 62nd char of encoding
			s = s.Replace('_', '/'); // 63rd char of encoding
			switch (s.Length%4) // Pad with trailing '='s
			{
				case 0:
					break; // No pad chars in this case
				case 2:
					s += "==";
					break; // Two pad chars
				case 3:
					s += "=";
					break; // One pad char
				default:
					throw new Exception("Illegal base64url string!");
			}
			return Convert.FromBase64String(s); // Standard base64 decoder
		}

		public static byte[] GetBytes(this string str)
		{
			return Encoding.ASCII.GetBytes(str);
		}

		public static string GetString(this byte[] bytes)
		{
			return Encoding.ASCII.GetString(bytes);
		}
	}
}
