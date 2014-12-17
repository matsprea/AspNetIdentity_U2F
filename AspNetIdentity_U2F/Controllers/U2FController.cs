using AspNetIdentity_U2F.DAL;
using IdentitySample.Models;
using Microsoft.AspNet.Identity;
using Microsoft.AspNet.Identity.Owin;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using System.Web;
using System.Web.Mvc;
using U2F;
using U2F.Server;
using U2F.Server.Data;
using U2F.Server.Impl;
using U2F.Server.Message;

namespace AspNetIdentity_U2F.Controllers
{
	[Authorize]
	public class U2FController : Controller
	{
		private ApplicationUserManager _userManager;

		private ApplicationUserManager UserManager
		{
			get { return _userManager ?? HttpContext.GetOwinContext().GetUserManager<ApplicationUserManager>(); }
			set { _userManager = value; }
		}

		private readonly IU2FServer _u2fServer;
		private readonly IDataStore _dataStore;


		public U2FController()
		{
			//_dataStore = new MemoryDataStore(new SessionIdGenerator());
			_dataStore = new U2FDbContext(new SessionIdGenerator());

			_u2fServer = new U2FServerReferenceImpl(new ChallengeGeneratorImpl(), _dataStore, new BouncyCastleCrypto(), Properties.Settings.Default.origins.Cast<string>());
		}

		private string AppId()
		{
			var appId = (HttpContext.Request.IsSecureConnection ? "https://" : "http://") + HttpContext.Request.Headers.Get("Host");
			return appId; //.GetBytes().Base64Urlencode();
		}


		[AcceptVerbs("POST")]
		public async Task<ActionResult> BeginEnroll(bool reregistration)
		{
			var user = await UserManager.FindByIdAsync(User.Identity.GetUserId());
			if (user == null)
				return null;

			var singleEnrollment = !reregistration;

			RegistrationRequest registrationRequest;
			IList<SignRequest> signRequests;
			try
			{
				registrationRequest = _u2fServer.GetRegistrationRequest(user.Id, AppId());

				signRequests = singleEnrollment
					? _u2fServer.GetSignRequest(user.Id, AppId())
					: new List<SignRequest>();
			}
			catch (U2FException e)
			{
				return null;
			}

			var signData = signRequests.Select(sr => new
			{
				appId = sr.AppId,
				challenge = sr.Challenge,
				version = sr.Version,
				keyHandle = sr.KeyHandle
			}).ToArray();

			var enrollData = new
			{
				appId = registrationRequest.AppId,
				challenge = registrationRequest.Challenge,
				version = registrationRequest.Version
			};

			var result = new
			{
				enroll_data = enrollData,
				sign_data = signData,
				sessionId = registrationRequest.SessionId
			};

			return Json(result);
		}

		[AcceptVerbs("POST")]
		public async Task<ActionResult> FinishEnroll(string registrationData, string clientData, string sessionId)
		{
			// Simple XSRF protection. We don't want users to be tricked into
			// submitting other people's enrollment data. Here we're just checking 
			// that it's the same user that also started the enrollment - you might
			// want to do something more sophisticated.
			var user = await UserManager.FindByIdAsync(User.Identity.GetUserId());
			var expectedUser = _dataStore.GetEnrollSessionData(sessionId).AccountName;

			if (user.Id != expectedUser)
			{
				return null;
			}

			var registrationResponse = new RegistrationResponse(registrationData, clientData, sessionId);

			SecurityKeyData newSecurityKeyData;
			try
			{
				var millis = (long) (DateTime.Now - new DateTime(1970, 1, 1)).TotalMilliseconds;
				newSecurityKeyData = _u2fServer.ProcessRegistrationResponse(registrationResponse, millis);
			}
			catch (U2FException e)
			{
				return null;
			}

			var response = new
			{
				enrollment_time = newSecurityKeyData.EnrollmentTime,
				key_handle = newSecurityKeyData.KeyHandle.ToHex(),
				public_key = newSecurityKeyData.PublicKey.ToHex(),
				issuer = newSecurityKeyData.AttestationCert.Issuer
			};

			return Json(response);
		}


		[AcceptVerbs("POST")]
		public async Task<ActionResult> BeginSign()
		{
			var user = await UserManager.FindByIdAsync(User.Identity.GetUserId());

			var signRequests = new List<SignRequest>();
			try
			{
				signRequests.AddRange(_u2fServer.GetSignRequest(user.Id, AppId()));
			}
			catch (U2FException e)
			{
				return null;
			}

			var signServerData = signRequests.Select(sr => new
			{
				appId = sr.AppId,
				challenge = sr.Challenge,
				version = sr.Version,
				keyHandle = sr.KeyHandle,
				sessionId = sr.SessionId
			});

			return Json(signServerData);
		}

		[HttpPost]
		public async Task<ActionResult> FinishSign(string keyHandle, string sessionId, string clientData, string signatureData)
		{
			var sessionData = _dataStore.GetSignSessionData(sessionId);

			// Simple XSRF protection. We don't want users to be tricked into
			// submitting other people's enrollment data. Here we're just checking 
			// that it's the same user that also started the enrollment - you might
			// want to do something more sophisticated.
			var user = await UserManager.FindByIdAsync(User.Identity.GetUserId());

			var expectedUser = sessionData.AccountName;
			if (user.Id != expectedUser)
			{
				return null;
			}


			var signResponse = new SignResponse(clientData, signatureData, sessionData.Challenge.Base64Urlencode(), sessionId,
				sessionData.AppId, keyHandle);
			SecurityKeyData securityKeyData;
			try
			{
				securityKeyData = _u2fServer.ProcessSignResponse(signResponse);
			}
			catch (U2FException e)
			{
				return null;
			}

			var response = new
			{
				enrollment_time = securityKeyData.EnrollmentTime,
				key_handle = securityKeyData.KeyHandle.ToHex(),
				public_key = securityKeyData.PublicKey.ToHex(),
				issuer = securityKeyData.AttestationCert.Issuer
			};

			return Json(response);
		}

		[AcceptVerbs("POST")]
		public async Task<ActionResult> GetTokens()
		{
			var user = await UserManager.FindByIdAsync(User.Identity.GetUserId());

			var sk = _u2fServer.GetAllSecurityKeys(user.Id);

			var resultList = sk.Select(s => new
			{
				enrollment_time = s.EnrollmentTime,
				key_handle = s.KeyHandle.ToHex(),
				public_key = s.PublicKey.ToHex(),
				issuer = s.AttestationCert.Issuer
			}).ToList();

			return Json(resultList);
		}

		[AcceptVerbs("POST")]
		public async Task<ActionResult> RemoveToken(string public_key)
		{
			var user = await UserManager.FindByIdAsync(User.Identity.GetUserId());

			try
			{
				_u2fServer.RemoveSecurityKey(user.Id, public_key.FromHex());
			}
			catch (U2FException e)
			{
				return null;
			}
			catch (Exception e)
			{
				return null;
			}

			return Json(new {status = "ok"});
		}
	}
}
