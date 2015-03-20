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

import mock
import time

from ntlmlib.messages import TargetInfo
from ntlmlib.constants import NegotiateFlag
from ntlmlib.authentication import PasswordAuthentication


class GeneralAuthenticationTestCase(unittest.TestCase):

    def test_initialise_without_username_or_password(self):
        authenticator = PasswordAuthentication('asgard', 'odin', None)
        self.assertIsNotNone(authenticator)

    def test_get_domain(self):
        authentication = PasswordAuthentication('asgard', 'odin', 'yggdrasill')
        self.assertEqual(authentication.get_domain(), 'asgard')

    def test_get_username(self):
        authentication = PasswordAuthentication('asgard', 'odin', 'yggdrasill')
        self.assertEqual(authentication.get_username(), 'odin')

    def test_get_password(self):
        authentication = PasswordAuthentication('asgard', 'odin', 'yggdrasill')
        self.assertEqual(authentication.get_password(), 'yggdrasill')

    def test_get_compatibility_level(self):
        compatibility = {'compatibility': 1}
        authentication = PasswordAuthentication('asgard', 'odin', 'yggdrasill', **compatibility)
        self.assertEqual(authentication.get_compatibility_level(), 1)

    def test_get_password_using_hashes_should_raise_exception(self):
        hashes = {'ansi_hash': 'dummy', 'unicode_hash': 'dummy', 'challenge': 'dummy'}
        authentication = PasswordAuthentication('asgard', 'odin', hashes)
        self.assertRaises(Exception, authentication.get_password())


class LmAuthenticationTestCase(unittest.TestCase):
    """
    Windows 9x and NT 3.5 Lan Manager Authentication Unit Tests
    """
    @classmethod
    def setUpClass(cls):
        options = {'compatibility': 1}
        #
        cls.authentication = PasswordAuthentication('asgard', 'odin', 'SecREt01', **options)

    # Pre-Computed NTLM Challenges and Responses used for Unit Tests
    class Lm(object):
        default_flags = NegotiateFlag.NTLMSSP_UNICODE
        server_challenge = str(binascii.unhexlify('0123456789abcdef'))
        client_challenge = str(binascii.unhexlify('06a0c4a0adb308a3'))
        user_session_key = str(binascii.unhexlify('4beff6b810fbe3eccce91a50500cd7f6'))
        ansi_hash = str(binascii.unhexlify('c337cd5cbd44fc9782a667af6d427c6de67c20c2d3e77c56'))
        unicode_hash = str(binascii.unhexlify('25a98c1c31e81847466b29b2df4680f39958fb8c213a9cc6'))

    @unittest.skip("need a Windows NT4 client to test")
    def test_get_lm_response(self):
        flags = self.lm.default_flags
        result = self.authentication.get_lm_response(flags, self.lm.server_challenge)
        self.assertEqual(result, self.lm.ansi_hash)

    @unittest.skip("need a Windows NT4 client to test")
    def test_get_ntlm_response(self):
        flags = self.lm.default_flags
        result = self.authentication.get_ntlm_response(flags, self.lm.server_challenge)
        self.assertEqual(result, self.lm.unicode_hash)

    @unittest.skip("need a Windows NT4 client to test")
    def test_get_lm_response_when_server_offers_ntlm2(self):
        flags = self.lm.default_flags | NegotiateFlag.NTLMSSP_NTLM2_KEY
        result = self.authentication.get_lm_response(flags, self.lm.server_challenge)
        self.assertEqual(result, self.lm.ansi_hash)

    @unittest.skip("Unable to validate expected output against a Windows server")
    def test_get_ntlm_response_when_server_offers_ntlm2(self):
        flags = self.lm.default_flags | NegotiateFlag.NTLMSSP_NTLM2_KEY
        result = self.authentication.get_ntlm_response(flags, self.lm.server_challenge)
        self.assertEqual(result, self.lm.ansi_hash)

    @unittest.skip("Unable to validate expected output against a Windows server")
    def test_lm_session_key(self):
        flags = self.lm.default_flags
        result = self.authentication.get_session_key(flags, self.lm.server_challenge)
        self.assertEqual(result, self.lm.ansi_hash)

    @unittest.skip("Unable to validate expected output against a Windows server")
    def test_lm_session_key_with_negotiate_lm_key_weakened_to_40_bits(self):
        flags = self.lm.default_flags | NegotiateFlag.NTLMSSP_LM_KEY
        result = self.authentication.get_session_key(flags, self.lm.server_challenge)
        self.assertEqual(result, self.lm.ansi_hash)

    @unittest.skip("Unable to validate expected output against a Windows server")
    def test_lm_session_key_with_negotiate_lm_key_weakened_to_56_bits(self):
        flags = self.lm.default_flags | NegotiateFlag.NTLMSSP_LM_KEY | NegotiateFlag.NTLMSSP_NEGOTIATE_56
        result = self.authentication.get_session_key(flags, self.lm.server_challenge)
        self.assertEqual(result, self.lm.ansi_hash)

    @unittest.skip("Unable to validate expected output against a Windows server")
    def test_lm_session_key_with_negotiate_key_exchange(self):
        flags = self.lm.default_flags | NegotiateFlag.NTLMSSP_KEY_EXCHANGE
        result = self.authentication.get_session_key(flags, self.lm.server_challenge)
        self.assertEqual(result, self.lm.ansi_hash)

    @unittest.skip("Unable to validate expected output against a Windows server")
    def test_lm_session_key_when_server_offers_ntlm2(self):
        flags = self.lm.default_flags | NegotiateFlag.NTLMSSP_LM_KEY | NegotiateFlag.NTLMSSP_NTLM2_KEY
        result = self.authentication.get_session_key(flags, self.lm.server_challenge)
        self.assertEqual(result, self.lm.ansi_hash)

    lm = Lm()


class NtlmAuthenticationTestCase(unittest.TestCase):
    """
    Windows 9x and NT4 Pre-SP4 Authentication Unit Tests
    """
    @classmethod
    def setUpClass(cls):
        options = {'compatibility': 2}
        cls.authentication = PasswordAuthentication('DOMAIN', 'user', 'SecREt01', **options)

    # Pre-Computed NTLM Challenges and Responses used for Unit Tests
    # see http://davenport.sourceforge.net/ntlm.html#theNtlmResponse
    class Ntlm(object):
        default_flags = NegotiateFlag.NTLMSSP_UNICODE
        server_challenge = str(binascii.unhexlify('0123456789abcdef'))
        client_challenge = str(binascii.unhexlify('ffffff0011223344'))
        user_session_key = str(binascii.unhexlify('4beff6b810fbe3eccce91a50500cd7f6'))
        ansi_hash = str(binascii.unhexlify('25a98c1c31e81847466b29b2df4680f39958fb8c213a9cc6'))
        unicode_hash = str(binascii.unhexlify('25a98c1c31e81847466b29b2df4680f39958fb8c213a9cc6'))

    @unittest.skip("Update the test since version tokens and flags were corrected")
    def test_get_lm_response(self):
        flags = self.ntlm.default_flags
        result = self.authentication.get_lm_response(flags, self.ntlm.server_challenge)
        self.assertEqual(result, self.ntlm.ansi_hash)

    @unittest.skip("Update the test since version tokens and flags were corrected")
    def test_get_ntlm_response(self):
        flags = self.ntlm.default_flags
        result = self.authentication.get_ntlm_response(flags, self.ntlm.server_challenge)
        self.assertEqual(result, self.ntlm.unicode_hash)

    @mock.patch('os.urandom')
    @unittest.skip("Unable to validate expected output against a Windows server")
    def test_get_ntlm_user_session_key(self, mock_random):
        mock_random.return_value = self.ntlm.client_challenge
        # NTLM responses are achieved with an Lan Manager Level of 2
        result = self.authentication.get_session_key(self.ntlm.server_challenge)
        self.assertEqual(result, self.ntlm.user_session_key)

    ntlm = Ntlm()


class Ntlmv2AuthenticationTestCase(unittest.TestCase):
    """
    NTLMv2 (Windows NT4 SP4 and Later Authentication Unit Tests)
    """
    # Pre-Computed NTLM Challenges and Responses used for Unit Tests
    # These can be verified at http://davenport.sourceforge.net/ntlm.html#theLmv2Response
    class Ntlmv2_davenport(object):
        time = time.struct_time((2003, 6, 17, 10, 00, 00, 00, 00, 0))
        client_challenge = str(binascii.unhexlify('ffffff0011223344'))
        server_challenge = str(binascii.unhexlify('0123456789abcdef'))
        user_session_key = str(binascii.unhexlify('4beff6b810fbe3eccce91a50500cd7f6'))
        lmv2_response   = str(binascii.unhexlify('d6e6152ea25d03b7c6ba6629c2d6aaf0ffffff0011223344'))
        target_info     = str(binascii.unhexlify('02000c0044004f004d00410049004e0001000c0053004500520056004500520004'
                                                 '00140064006f006d00610069006e002e0063006f006d0003002200730065007200'
                                                 '7600650072002e0064006f006d00610069006e002e0063006f006d0000000000'))
        ntlmv2_response = str(binascii.unhexlify('cbabbca713eb795d04c97abc01ee498301010000000000000090d336b734c301'
                                                 'ffffff00112233440000000002000c0044004f004d00410049004e0001000c00'
                                                 '5300450052005600450052000400140064006f006d00610069006e002e006300'
                                                 '6f006d00030022007300650072007600650072002e0064006f006d0061006900'
                                                 '6e002e0063006f006d000000000000000000'))

    @classmethod
    def setUpClass(cls):
        cls.flags = NegotiateFlag.NTLMSSP_UNICODE
        cls.target_info = TargetInfo()
        cls.target_info.from_string(cls.ntlmv2_davenport.target_info)
        cls.build_mocks()

    @classmethod
    @mock.patch('os.urandom')
    def build_mocks(cls, mock_random):
        options = {'compatibility': 3, 'timestamp': False}
        mock_random.return_value = cls.ntlmv2_davenport.client_challenge
        cls.authentication = PasswordAuthentication('DOMAIN', 'user', 'SecREt01', **options)

    def test_get_lm_response(self):
        flags = self.flags
        result = self.authentication.get_lm_response(flags, self.ntlmv2_davenport.server_challenge)
        self.assertEqual(result, self.ntlmv2_davenport.lmv2_response)

    @mock.patch('time.gmtime')
    def test_get_ntlm_response(self, mock_time):
        flags = self.flags
        target_info = TargetInfo()
        target_info.from_string(self.ntlmv2_davenport.target_info)
        mock_time.return_value = self.ntlmv2_davenport.time
        response, key, info = self.authentication.get_ntlm_response(flags,
                                                                    self.ntlmv2_davenport.server_challenge, target_info)
        self.assertEqual(response, self.ntlmv2_davenport.ntlmv2_response)

    def test_get_ntlmv2_user_session_key(self):
        self.assertTrue(True)

    ntlmv2_davenport = Ntlmv2_davenport()




if __name__ == '__main__':
    unittest.main()