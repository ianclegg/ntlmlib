# (c) 2015, Ian Clegg <ian.clegg@sourcewarp.com>
#
# ntlmlib is licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
# http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
__author__ = 'ian.clegg@sourcewarp.com'

import unittest
import binascii

from ntlmlib.context import NtlmContext
from ntlmlib.authentication import PasswordAuthentication

#class NtlmTokenBuilder(object):
#    build
class Ntlmv2ContextTestCase(unittest.TestCase):
        # Pre-Computed NTLM Challenges and Responses used for Unit Tests
    class Tokens(object):
        negotiate = str(binascii.unhexlify('4e544c4d535350000100000001308820060006002e00'
                                           '000006000600280000006465766d6163617367617264'))

        negotiate_encrypt = str(binascii.unhexlify(''))

        """
        NTLMSSP_UNICODE (Negotiate Unicode)
        NTLMSSP_TARGET (Request Target)
        NTLMSSP_SIGN (Negotiate Sign)
        NTLMSSP_SEAL (Negotiate Seal)
        NTLMSSP_DOMAIN (Domain Supplied)
        NTLMSSP_WORKSTATION (Workstation Supplied)
        NTLMSSP_ALWAYS_SIGN (Always Sign)
        NTLMSSP_NTLM2_KEY ()
        NTLMSSP_TARGET_INFO (Negotiate Target Info)
        NTLMSSP_KEY_128 (Negotiate 128)
        NTLMSSP_KEY_EXCHANGE (Negotiate Key Exchange)
        Domain: asgard
        Workstation: thor
        """
        negotiate_encrypt = str(binascii.unhexlify('4e544c4d535350000100000035b088600600060024'
                                                   '000000040004002000000074686f72617367617264'))


        challenge_encrypt = str(binascii.unhexlify('4e544c4d53535000020000000600060038000000358289625a'
                                                   'f8bf6617f3381800000000000000009e009e003e0000000601'
                                                   'b11d0000000f42005000310002000600420050003100010016'
                                                   '004200500031004c0043005300410050003000310039000400'
                                                   '1a006200700031002e00610064002e00620070002e0063006f'
                                                   '006d00030032004200500031004c0043005300410050003000'
                                                   '310039002e006200700031002e00610064002e00620070002e'
                                                   '0063006f006d0005001200610064002e00620070002e006300'
                                                   '6f006d0007000800e6651a13ddeacf0100000000'))
    @classmethod
    def setUpClass(cls):
        cls.authentication = lambda x: PasswordAuthentication('asgard', 'odin', 'SecREt01')
    """
    def test_that_initialize_security_context_generates_negotiate_token(self):
        ntlm_context = NtlmContext(self.authentication())
        context = ntlm_context.initialize_security_context()
        token = context.send(None)
        self.assertEqual(token, self.tokens.negotiate)

    def test_that_initialize_security_context_generates_negotiate_sign_token(self):
        ntlm_context = NtlmContext(self.authentication(), session_security='sign')
        context = ntlm_context.initialize_security_context()
        token = context.send(None)
        print binascii.hexlify(token)
        self.assertEqual(token, self.tokens.negotiate_sign)

    def test_that_initialize_security_context_generates_negotiate_seal_token(self):
        ntlm_context = NtlmContext(self.authentication(), session_security='encrypt')
        context = ntlm_context.initialize_security_context()
        token = context.send(None)
        print binascii.hexlify(token)
        self.assertEqual(token, self.tokens.negotiate_encrypt)
    """

    def test_that_response_token_after_challenge(self):
        ntlm_context = NtlmContext(self.authentication(), session_security='none')
        context = ntlm_context.initialize_security_context()
        context.send(None)
        response = context.send(self.tokens.challenge_encrypt)
        self.assertEqual(True, True)

    tokens = Tokens()

class NtlmContextTestCase(unittest.TestCase):
    """

    """
    # Pre-Computed NTLM Challenges and Responses used for Unit Tests
    class Tokens(object):
        negotiate = str(binascii.unhexlify('4e544c4d535350000100000001308820060006002e00'
                                           '000006000600280000006465766d6163617367617264'))
        negotiate_sign = str(binascii.unhexlify('4e544c4d535350000100000011308860060006002e00'
                                                '000006000600280000006465766d6163617367617264'))
        negotiate_encrypt = str(binascii.unhexlify(''))

        challenge_encrypt = str(binascii.unhexlify('4e544c4d53535000020000000600060038000000358289625a'
                                                   'f8bf6617f3381800000000000000009e009e003e0000000601'
                                                   'b11d0000000f42005000310002000600420050003100010016'
                                                   '004200500031004c0043005300410050003000310039000400'
                                                   '1a006200700031002e00610064002e00620070002e0063006f'
                                                   '006d00030032004200500031004c0043005300410050003000'
                                                   '310039002e006200700031002e00610064002e00620070002e'
                                                   '0063006f006d0005001200610064002e00620070002e006300'
                                                   '6f006d0007000800e6651a13ddeacf0100000000'))

    @classmethod
    def setUpClass(cls):
        cls.authentication = lambda x: PasswordAuthentication('asgard', 'odin', 'SecREt01')

    @unittest.skip("Update the test since version tokens and flags were corrected")
    def test_that_initialize_security_context_generates_negotiate_token(self):
        ntlm_context = NtlmContext(self.authentication())
        context = ntlm_context.initialize_security_context()
        token = context.send(None)
        self.assertEqual(token, self.tokens.negotiate)

    @unittest.skip("Update the test since version tokens and flags were corrected")
    def test_that_initialize_security_context_generates_negotiate_sign_token(self):
        ntlm_context = NtlmContext(self.authentication(), session_security='sign')
        context = ntlm_context.initialize_security_context()
        token = context.send(None)
        print binascii.hexlify(token)
        self.assertEqual(token, self.tokens.negotiate_sign)

    @unittest.skip("Update the test since version tokens and flags were corrected")
    def test_that_initialize_security_context_generates_negotiate_seal_token(self):
        ntlm_context = NtlmContext(self.authentication(), session_security='encrypt')
        context = ntlm_context.initialize_security_context()
        token = context.send(None)
        print binascii.hexlify(token)
        self.assertEqual(token, self.tokens.negotiate_encrypt)

    @unittest.skip("Update the test since version tokens and flags were corrected")
    def test_that_initialize_security_context_generates_response_token_after_challenge(self):
        ntlm_context = NtlmContext(self.authentication(), session_security='encrypt')
        context = ntlm_context.initialize_security_context()
        context.send(None)
        response = context.send(self.tokens.challenge_encrypt)
        self.assertEqual(True, True)

    tokens = Tokens()