AspNetIdentity_U2F
==================

This project will provide a [FIDO Alliance](https://fidoalliance.org/) Universal 2nd Factor (U2F) provider for Asp.Net Identity 2.0

The U2F implementation is a C# porting of [google/u2f-ref-code](https://github.com/google/u2f-ref-code) Java implementation

Status
==================
  - U2F .Net library
    - porting **COMPLETED** from Java to C#
  - IdentityProvider
    - Enrollment of U2F token: **WORKING** with multiple U2F tokens
    - Login: **WORKING** only when just *ONE* U2F token is enrolled
  - Sample application
    - UX **to be improved** 
