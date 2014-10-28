using U2F.Key.Messages;

namespace U2F.Key
{
	public interface IU2FKey {
		RegisterResponse Register(RegisterRequest registerRequest);

		AuthenticateResponse Authenticate(AuthenticateRequest authenticateRequest);
	}
}