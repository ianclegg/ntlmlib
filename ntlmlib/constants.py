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


class NegotiateFlag(object):
    NTLMSSP_NEGOTIATE_56       = 0x80000000
    NTLMSSP_KEY_EXCHANGE       = 0x40000000
    NTLMSSP_KEY_128            = 0x20000000
    NTLMSSP_RESERVED_r1        = 0x10000000
    NTLMSSP_RESERVED_r2        = 0x08000000
    NTLMSSP_RESERVED_r3_       = 0x04000000
    NTLMSSP_VERSION            = 0x02000000
    NTLMSSP_RESERVED_r4        = 0x01000000
    NTLMSSP_TARGET_INFO        = 0x00800000
    NTLMSSP_NOT_NT_KEY         = 0x00400000
    # NTLMSSP_                 = 0x00200000
    # NTLMSSP_                 = 0x00100000
    NTLMSSP_NTLM2_KEY          = 0x00080000
    NTLMSSP_TARGET_TYPE_SHARE  = 0x00040000
    NTLMSSP_TARGET_TYPE_SERVER = 0x00020000
    NTLMSSP_TARGET_TYPE_DOMAIN = 0x00010000
    NTLMSSP_ALWAYS_SIGN        = 0x00008000
    NTLMSSP_LOCAL_CALL         = 0x00004000
    NTLMSSP_WORKSTATION        = 0x00002000
    NTLMSSP_DOMAIN             = 0x00001000
    NTLMSSP_ANONYMOUS          = 0x00000800
    NTLMSSP_RESERVED_r8        = 0x00000400
    NTLMSSP_NTLM_KEY           = 0x00000200
    NTLMSSP_NETWARE            = 0x00000100
    NTLMSSP_LM_KEY             = 0x00000080
    NTLMSSP_DATAGRAM           = 0x00000040
    NTLMSSP_SEAL               = 0x00000020
    NTLMSSP_SIGN               = 0x00000010
    NTLMSSP_RESERVED_r10       = 0x00000008
    NTLMSSP_TARGET             = 0x00000004
    NTLMSSP_OEM                = 0x00000002
    NTLMSSP_UNICODE            = 0x00000001


class SessionSecurity(object):
    CLIENT_SEALING = ""
    CLIENT_SIGNING = ""