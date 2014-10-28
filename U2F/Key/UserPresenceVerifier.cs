namespace U2F.Key
{
	public abstract class UserPresenceVerifier
	{
		public const byte USER_PRESENT_FLAG = (byte) 0x01;
		public abstract byte VerifyUserPresence();
	}
}