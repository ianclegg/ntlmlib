ntlmlib |travis| |version| |support|
====================================
**A robust, fast and efficient 'first-class' Python Library for NTLM authentication, signing and encryption**

.. |travis| image:: https://travis-ci.org/ianclegg/ntlmlib.svg?branch=master
            :target: https://travis-ci.org/ianclegg/ntlmlib

.. |version| image:: https://img.shields.io/pypi/v/ntlmlib.svg
             :target: https://pypi.python.org/pypi/ntlmlib/

.. |support| image:: https://img.shields.io/pypi/pyversions/ntlmlib.svg
              :target: https://pypi.python.org/pypi/ntlmlib/

Authentication should be so easy its taken for granted; but that doesnt make it easy. It's probably why most libraries implemented only the most basic features, emulating decade old versions like that of Windows 2000 or XP and ignoring session security altogether

ntlmlib gives Python developers the support they deserve. It negotiates the strongest session security and uses this
to digitally sign timestamped authentication tokens which help mitigate replay and man-in-the-middle attacks - this has
been standard on Windows for many years, but not available in pure Python. Now python NTLM clients can pass the toughest
cyber security audits.

Naturally, ntlmlib is also highly configurable, allowing you to easily set balance between compatibility with legacy
systems and security depending on you application.

I would not have been able to use Python in production systems without the NTLM session security provided by ntlmlib.

.. code-block:: python

    # Setup the NTLM context with your credentials, optionally set LAN Manager Compatibility and required integrity
    auth = PasswordAuthentication('SERVER2012', 'Administrator', 'Pa55w0rd')
    ntlm_context = NtlmContext(auth, session_security='none')

    # Generate the initial negotiate token
    context = ntlm_context.initialize_security_context()
    negotiate = context.send(None)

    # < Now send the negotiate token to the sever and receive the challenge >

    # Generate the authenticate token from the challenge
    authenticate = context.send(challenge)

    #< Now send the authenticate token to the server to complete authentication >
    ...

Features
--------

- Support for LM, NTLM and NTLMv2 authentication
- Support for NTLM1 and NTLM2 Extended Session Security with 40bit, 56bit and 128bit key derivation and key exchange
- Support for Session Security Signing (Sign and Verify) and Encryption (Sealing and Unsealing)
- Support for enhanced security using MICs (Message Integrity Code)
- Support for enhanced security using Channel Binding Tokens
- Tested against Windows NT4 RTM through to Windows 10
- Well organised and commented with supporting unit tests and documentation
- Super safe and easy to use API


Installation
------------

To install ntlmlib, simply:

.. code-block:: bash

    $ pip install ntlmlib


Backlog
-------

- Logging is not fully implemented
- Test cases are no fully implemented


Contributions
-------------

#. Check for open issues or open a fresh issue to start a discussion around a feature idea or a bug.
#. If you feel uncomfortable or uncertain about an issue or your changes, feel free to email me
#. Fork `the repository`_ on GitHub to start making your changes to the **master** branch (or branch off of it).
#. Write a test which shows that the bug was fixed or that the feature works as expected.
#. Send a pull request and bug the maintainer until it gets merged and published.

.. _`the repository`: http://github.com/ianclegg/ntlmlib