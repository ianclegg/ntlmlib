"""
 (c) 2015, Ian Clegg <ian.clegg@sourcewarp.com>

 ntlmlib is licensed under the Apache License, Version 2.0 (the "License");
 you may not use this file except in compliance with the License.
 You may obtain a copy of the License at

 http://www.apache.org/licenses/LICENSE-2.0

 Unless required by applicable law or agreed to in writing, software
 distributed under the License is distributed on an "AS IS" BASIS,
 WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 See the License for the specific language governing permissions and
 limitations under the License.
"""
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
        self.assertNotEqual(None, authenticator)

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

    def test_lm_compatibility_level_too_low(self):
        compatibility = {'compatibility': -1}
        test = lambda: PasswordAuthentication('asgard', 'odin', 'yggdrasill', **compatibility)
        self.assertRaises(Exception, test)

    def test_lm_compatibility_level_too_high(self):
        compatibility = {'compatibility': 6}
        test = lambda: PasswordAuthentication('asgard', 'odin', 'yggdrasill', **compatibility)
        self.assertRaises(Exception, test)

    # TODO: For completeness, we could do with tests for ntowfv2, ntowfv1 and lmowfv1, although
    # TODO: they are also indirectly covered by the test cases below already

class LmAuthenticationTestCase(unittest.TestCase):
    """
    Windows 9x and NT 3.5 Lan Manager Authentication Unit Tests
    """
    # Pre-Computed NTLM Challenges and Responses used for Unit Tests
    # see http://davenport.sourceforge.net/ntlm.html#theNtlmResponse
    # NTLMv1 Authentication; NTLM1 Signing and Sealing Using the LM User Session Key
    class Lm(object):
        default_flags = NegotiateFlag.NTLMSSP_UNICODE
        server_challenge = binascii.unhexlify('6da297169f7aa9c2')
        user_session_key = binascii.unhexlify('624aac413795cdc10000000000000000')
        lm_response = binascii.unhexlify('2e17884ea16177e2b751d53b5cc756c3cd57cdfd6e3bf8b9')

    @classmethod
    def setUpClass(cls):
        options = {'compatibility': 0}
        cls.authentication = PasswordAuthentication('TESTNT', 'test', 'test1234', **options)

    def test_get_lm_response(self):
        flags = self.lm.default_flags
        response, key = self.authentication.get_lm_response(flags, self.lm.server_challenge)
        self.assertEqual(response, self.lm.lm_response)

    def test_lm_session_key(self):
        flags = self.lm.default_flags
        response, key = self.authentication.get_lm_response(flags, self.lm.server_challenge)
        self.assertEqual(key, self.lm.user_session_key)

    lm = Lm()


class NtlmAuthenticationTestCase(unittest.TestCase):
    """
    Windows 9x and NT4 Pre-SP4 Authentication Unit Tests
    """
    @classmethod
    def setUpClass(cls):
        cls.build_mocks()

    @classmethod
    @mock.patch('os.urandom')
    def build_mocks(cls, mock_random):
        options = {'compatibility': 2 }
        mock_random.return_value = cls.ntlm.client_challenge
        cls.authentication = PasswordAuthentication('TESTNT', 'test', 'test1234', **options)

    # Pre-Computed NTLM Challenges and Responses used for Unit Tests
    # see http://davenport.sourceforge.net/ntlm.html#theNtlmResponse
    # NTLMv1 Authentication; NTLM1 Signing and Sealing Using the NTLM User Session Key
    class Ntlm(object):
        default_flags = NegotiateFlag.NTLMSSP_UNICODE
        client_challenge = binascii.unhexlify('404d1b6f69152580')
        server_challenge = binascii.unhexlify('b019d38bad875c9d')
        user_session_key = binascii.unhexlify('ae33a32dca8c9821844f740d5b3f4d6c')
        ntlmv1_response = binascii.unhexlify('e6285df3287c5d194f84df1a94817c7282d09754b6f9e02a')

    # The lm response is the same as the ntlmv1 response with LMCompatibilityLevel 2
    def test_get_lm_response(self):
        flags = self.ntlm.default_flags
        response, key = self.authentication.get_lm_response(flags, self.ntlm.server_challenge)
        self.assertEqual(response, self.ntlm.ntlmv1_response)

    def test_get_ntlm_response(self):
        flags = self.ntlm.default_flags
        response, key, info = self.authentication.get_ntlm_response(flags, self.ntlm.server_challenge)
        self.assertEqual(response, self.ntlm.ntlmv1_response)

    def test_get_ntlm_user_session_key(self):
        flags = self.ntlm.default_flags
        response, key, info = self.authentication.get_ntlm_response(flags, self.ntlm.server_challenge)
        self.assertEqual(key, self.ntlm.user_session_key)

    ntlm = Ntlm()


class Ntlm2AuthenticationTestCase(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.build_mocks()

    @classmethod
    @mock.patch('os.urandom')
    def build_mocks(cls, mock_random):
        options = {'compatibility': 2}
        mock_random.return_value = cls.ntlm.client_challenge
        cls.authentication = PasswordAuthentication('TESTNT', 'test', 'test1234', **options)

    class Ntlm2(object):
        default_flags = NegotiateFlag.NTLMSSP_UNICODE | NegotiateFlag.NTLMSSP_NTLM2_KEY
        client_challenge = binascii.unhexlify('404d1b6f69152580')
        server_challenge = binascii.unhexlify('677f1c557a5ee96c')
        lm_response = binascii.unhexlify('404d1b6f6915258000000000000000000000000000000000')
        ntlm_response = binascii.unhexlify('ea8cc49f24da157f13436637f77693d8b992d619e584c7ee')
        lm_session_key = None

    def test_get_lm_response_when_NTLMSSP_NTLM2_KEY_set(self):
        flags = self.ntlm.default_flags
        response, key = self.authentication.get_lm_response(flags, self.ntlm.server_challenge)
        self.assertEqual(response, self.ntlm.lm_response)
        self.assertEqual(key, self.ntlm.lm_session_key)

    def test_get_ntlm_response_when_NTLMSSP_NTLM2_KEY_set(self):
        flags = self.ntlm.default_flags
        response, key, info = self.authentication.get_ntlm_response(flags, self.ntlm.server_challenge)
        self.assertEqual(response, self.ntlm.ntlm_response)

    ntlm = Ntlm2()


class Ntlmv2AuthenticationTestCase(unittest.TestCase):
    """
    NTLMv2 (Windows NT4 SP4 and Later Authentication Unit Tests)
    """
    # Pre-Computed NTLM Challenges and Responses used for Unit Tests
    # These can be verified at http://davenport.sourceforge.net/ntlm.html#theLmv2Response
    class Ntlmv2_davenport(object):
        time = time.struct_time((2003, 6, 17, 10, 00, 00, 00, 00, 0))
        client_challenge = binascii.unhexlify('ffffff0011223344')
        server_challenge = binascii.unhexlify('0123456789abcdef')
        user_session_key = binascii.unhexlify('4beff6b810fbe3eccce91a50500cd7f6')
        lmv2_response = binascii.unhexlify('d6e6152ea25d03b7c6ba6629c2d6aaf0ffffff0011223344')
        target_info = binascii.unhexlify('02000c0044004f004d00410049004e0001000c005300450052005600450052000400'
                                         '140064006f006d00610069006e002e0063006f006d00030022007300650072007600'
                                         '650072002e0064006f006d00610069006e002e0063006f006d0000000000')
        ntlmv2_response = binascii.unhexlify('cbabbca713eb795d04c97abc01ee498301010000000000000090d336b734c301'
                                             'ffffff00112233440000000002000c0044004f004d00410049004e0001000c00'
                                             '5300450052005600450052000400140064006f006d00610069006e002e006300'
                                             '6f006d00030022007300650072007600650072002e0064006f006d0061006900'
                                             '6e002e0063006f006d000000000000000000')

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
        response, key = self.authentication.get_lm_response(flags, self.ntlmv2_davenport.server_challenge)
        self.assertEqual(response, self.ntlmv2_davenport.lmv2_response)

    @mock.patch('time.gmtime')
    def test_get_ntlm_response(self, mock_time):
        flags = self.flags
        target_info = TargetInfo()
        target_info.from_string(self.ntlmv2_davenport.target_info)
        mock_time.return_value = self.ntlmv2_davenport.time
        response, key, info = self.authentication.get_ntlm_response(flags,
                                                                    self.ntlmv2_davenport.server_challenge, target_info)
        self.assertEqual(response, self.ntlmv2_davenport.ntlmv2_response)

    ntlmv2_davenport = Ntlmv2_davenport()

if __name__ == '__main__':
    unittest.main()