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

from ntlmlib.messages import NegotiateFlag
from ntlmlib.security import Ntlm1Signing
from ntlmlib.security import Ntlm1Sealing
from ntlmlib.security import Ntlm2Sealing

class Ntlm1SealingTestCase(unittest.TestCase):
    class Tokens(object):
            davenport_message = 'jCIFS'
            davenport_key = str(binascii.unhexlify('0102030405060708090a0b0c0d0e0f00'))

            # The davenport example sets replaces the randompad with a random value of 0x78010900
            # [MS-NLMP] states the randompad is overwritten with zero's; this signature has zero's
            davenport_signature = str(binascii.unhexlify('0100000000000000397420fe0e5a0f89'))

    def test_that_sign_generates_the_correct_signature(self):
        """

        """
        flags = NegotiateFlag.NTLMSSP_ALWAYS_SIGN | NegotiateFlag.NTLMSSP_SEAL
        session = Ntlm1Signing(flags, self.tokens.davenport_key)
        signature = session.wrap(self.tokens.davenport_message)
        self.assertEqual(self.tokens.davenport_signature, signature)
        pass

    def test_that_seal_encrypts_and_generates_the_signature(self):
        """

        """
        flags = NegotiateFlag.NTLMSSP_ALWAYS_SIGN | NegotiateFlag.NTLMSSP_SEAL
        session = Ntlm1Sealing(flags, self.tokens.davenport_key)
        ciphertext, signature = session.wrap(self.tokens.davenport_message)
        self.assertEqual(self.tokens.davenport_signature, signature)
        pass
    tokens = Tokens()


class Ntlm2SealingTestCase(unittest.TestCase):
    """
    4.2.4.4 GSS_WrapEx Examples
    """
    class Tokens(object):
        microsoft_message = str(binascii.unhexlify('50006c00610069006e007400650078007400'))
        microsoft_key = str(binascii.unhexlify('55555555555555555555555555555555'))
        microsoft_client_signature = str(binascii.unhexlify('010000007fb38ec5c55d497600000000'))
        microsoft_client_ciphertext = str(binascii.unhexlify('54e50165bf1936dc996020c1811b0f06fb5f'))
        microsoft_server_signature = str(binascii.unhexlify('01000000b298b847ce7c580700000000'))
        microsoft_server_ciphertext = str(binascii.unhexlify('160871b730ba74e946c453d7465b54278dd0'))

    def test_gss_wrap_client_side_128bit_key_exchange(self):
        flags = NegotiateFlag.NTLMSSP_ALWAYS_SIGN | NegotiateFlag.NTLMSSP_SEAL |\
                NegotiateFlag.NTLMSSP_KEY_128 | NegotiateFlag.NTLMSSP_KEY_EXCHANGE
        session = Ntlm2Sealing(flags, self.tokens.microsoft_key, 'client')
        cipher_text, signature = session.wrap(self.tokens.microsoft_message)

        self.assertEqual(self.tokens.microsoft_client_signature, signature)
        self.assertEqual(self.tokens.microsoft_client_ciphertext, cipher_text)

    def test_gss_unwrap_client_side_128bit_key_exchange(self):
        flags = NegotiateFlag.NTLMSSP_ALWAYS_SIGN | NegotiateFlag.NTLMSSP_SEAL |\
                NegotiateFlag.NTLMSSP_KEY_128 | NegotiateFlag.NTLMSSP_KEY_EXCHANGE
        session = Ntlm2Sealing(flags, self.tokens.microsoft_key, 'client')
        plain_text = session.unwrap(self.tokens.microsoft_server_ciphertext, self.tokens.microsoft_server_signature)

        self.assertEqual(self.tokens.microsoft_message, plain_text)

    def test_gss_wrap_server_side_128bit_key_exchange(self):
        flags = NegotiateFlag.NTLMSSP_ALWAYS_SIGN | NegotiateFlag.NTLMSSP_SEAL |\
                NegotiateFlag.NTLMSSP_KEY_128 | NegotiateFlag.NTLMSSP_KEY_EXCHANGE
        session = Ntlm2Sealing(flags, self.tokens.microsoft_key, 'server')
        ciphertext, signature = session.wrap(self.tokens.microsoft_message)

        self.assertEqual(self.tokens.microsoft_server_signature, signature)
        self.assertEqual(self.tokens.microsoft_server_ciphertext, ciphertext)

    def test_gss_unwrap_server_128bit_key_exchange(self):
        flags = NegotiateFlag.NTLMSSP_ALWAYS_SIGN | NegotiateFlag.NTLMSSP_SEAL |\
                NegotiateFlag.NTLMSSP_KEY_128 | NegotiateFlag.NTLMSSP_KEY_EXCHANGE
        session = Ntlm2Sealing(flags, self.tokens.microsoft_key, 'server')
        plain_text = session.unwrap(self.tokens.microsoft_client_ciphertext, self.tokens.microsoft_client_signature)

        self.assertEqual(self.tokens.microsoft_message, plain_text)

    tokens = Tokens()