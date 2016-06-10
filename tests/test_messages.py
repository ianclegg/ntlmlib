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

from ntlmlib.messages import TargetInfo
from ntlmlib.messages import Challenge


class TargetInfoTestCase(unittest.TestCase):
    class Tokens(object):
            davenport_server = 'SERVER'.encode('utf-16le')
            davenport_domain = 'DOMAIN'.encode('utf-16le')
            davenport_dns_server = 'server.domain.com'.encode('utf-16le')
            davenport_dns_domain = 'domain.com'.encode('utf-16le')
            davenport_info = binascii.unhexlify('02000c0044004f004d00410049004e0001000c0053004500520056004500520004'
                                                    '00140064006f006d00610069006e002e0063006f006d0003002200730065007200'
                                                    '7600650072002e0064006f006d00610069006e002e0063006f006d0000000000')

    def test_from_string_works_with_davenport_sample(self):
        """
        Davenport's NTLM documentation includes a sample TargetInfo structure, test this can be deserialized
        """
        target_info = TargetInfo()
        target_info.from_string(self.tokens.davenport_info)
        self.assertEqual(self.tokens.davenport_server, target_info[TargetInfo.NTLMSSP_AV_HOSTNAME][1])
        self.assertEqual(self.tokens.davenport_domain, target_info[TargetInfo.NTLMSSP_AV_DOMAINNAME][1])
        self.assertEqual(self.tokens.davenport_dns_server, target_info[TargetInfo.NTLMSSP_AV_DNS_HOSTNAME][1])
        self.assertEqual(self.tokens.davenport_dns_domain, target_info[TargetInfo.NTLMSSP_AV_DNS_DOMAINNAME][1])
        pass

    def test_to_string_works_with_davenport_sample(self):
        """
        Davenport's NTLM documentation includes a sample TargetInfo structure, test this can be deserialized
        """
        target_info = TargetInfo()
        target_info[TargetInfo.NTLMSSP_AV_DOMAINNAME] = self.tokens.davenport_domain
        target_info[TargetInfo.NTLMSSP_AV_HOSTNAME] = self.tokens.davenport_server
        target_info[TargetInfo.NTLMSSP_AV_DNS_DOMAINNAME] = self.tokens.davenport_dns_domain
        target_info[TargetInfo.NTLMSSP_AV_DNS_HOSTNAME] = self.tokens.davenport_dns_server
        self.assertEqual(self.tokens.davenport_info, target_info.get_data())
        pass

    tokens = Tokens()


class ChallengeTestCase(unittest.TestCase):

    class Tokens(object):
        windows_nt4 = binascii.unhexlify('4e544c4d53535000020000001200120028000000050202005fc3e1acb7'
                                         '7f3eab00000000000000004e0054003400530045005200560045005200'
                                         '64006500760065006c006f00700065002d0077003500730074003200380000000000')
        windows_2003 = binascii.unhexlify('4e544c4d53535000020000001e001e003800000035828a6220b171806b5b081e'
                                          '00000000000000008c008c00560000000502ce0e0000000f4400450056004500'
                                          '4c004f00500045002d0057003500530054003200380002001e00440045005600'
                                          '45004c004f00500045002d0057003500530054003200380001001e0044004500'
                                          '560045004c004f00500045002d0057003500530054003200380004001e006400'
                                          '6500760065006c006f00700065002d0077003500730074003200380003001e00'
                                          '64006500760065006c006f00700065002d0077003500730074003200380000000000')

    def test_from_string_works_with_Windows_NT4_challenege(self):
        """
        Windows NT4 does not include the OS Version or Target Info fields
        """
        challenge = Challenge()
        challenge.from_string(self.tokens.windows_nt4)
        self.assertEqual(challenge['os_version'], '')
        self.assertEqual(challenge['target_info_fields'], None)

    @unittest.skip("test not implemented yet")
    def test_from_string_works_with_Windows_2003_challenege_wihout_TargetInfo(self):
        """
        Windows XP SP2 and later, and Windows 2003 and later include both Target Info and Version information.
        According to the specification, TargetInfo may be empty
        """
        pass

    @unittest.skip("extractive version info is broken at the moment")
    def test_from_string_works_with_Windows_2003_challenege_with_targetinfo(self):
        """
        A sample Windows 2008 Challenege with Targetinfo set, only the domain name is set
        """
        challenge = Challenge()
        challenge.from_string(self.tokens.windows_2003)
        target_info = challenge['target_info_fields']
        domain_name = 'DEVELOPE-W5ST28'.encode('utf-16le')
        self.assertTupleEqual(challenge.get_os_version(), (5, 2, 3790))
        self.assertEqual(domain_name, target_info[TargetInfo.NTLMSSP_AV_DOMAINNAME][1])

    #@unittest.skip("this is broken at the moment")
    def test_from_string_works_with_Windows_2008_challenege_with_targetinfo(self):
        """
        A sample Windows 2008 Challenege with Targetinfo set, this includes
        Domain Name,
        """
        challenge = Challenge()
        challenge.from_string(self.tokens.windows_2003)
        target_info = challenge['target_info_fields']
        domain_name = 'DEVELOPE-W5ST28'.encode('utf-16le')
        # version information is broken at the moment
        #self.assertTupleEqual(challenge.get_os_version(), (5, 2, 3790))
        self.assertEqual(domain_name, target_info[TargetInfo.NTLMSSP_AV_DOMAINNAME][1])

    tokens = Tokens()



