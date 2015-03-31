# ntlmlib (ALPHA) [![Build Status](https://travis-ci.org/ianclegg/ntlmlib.svg?branch=master)](https://travis-ci.org/ianclegg/ntlmlib) [![Downloads](https://pypip.in/download/ntlmlib/badge.svg)](https://pypi.python.org/pypi/ntlmlib/) [![Latest Version](https://pypip.in/version/ntlmlib/badge.svg)](https://pypi.python.org/pypi/ntlmlib/)

## Vision:
A robust, fast and efficient 'first-class' Python Library for NTLM authentication, signing and encryption

- [x] Support for LM, NTLM and NTLMv2 authentication
- [x] Support for NTLM1 and NTLM2 Extended Session Security with 40bit, 56bit and 128bit key derivation and key exchange
- [x] Support for Session Security Signing (Sign and Verify) and Encryption (Sealing and Unsealing)
- [x] Support for enhanced security using MICs (Message Integrity Code)
- [ ] Support for enhanced security using Channel Binding Tokens
- [x] Tested against Windows NT4 RTM through to Windows 10
- [x] Well organised and commented with supporting unit tests and documentation
- [x] Super safe and easy to use API

Known Issues:
- Use of Lan Manger Session Keys is not implemented yet
- Channel Binding token generation is not implemented
- Logging is not fully implemented

Example:

```python
# Setup the NTLM context with your credentials, optionally set LAN Manager Compatibility and required integrity
auth = PasswordAuthentication('SERVER2012', 'Administrator', 'Pa55w0rd', compatibility=3, timestamp=True)
ntlm_context = NtlmContext(auth, session_security='none')

# Generate the initial negotiate token
context = ntlm_context.initialize_security_context()
negotiate = context.send(None)

# < Now send the negotiate token to the sever and receive the challenge >

# Generate the authenticate token from the challenge
authenticate = context.send(challenge)

# < Now send the authenticate token to the server to complete authentication >
```

