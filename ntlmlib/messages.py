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

import struct

from ntlmlib.structure import Structure
from constants import NegotiateFlag

try:
    from collections import OrderedDict
except ImportError:
    from ordereddict import OrderedDict

class Message(object):
    def dump_flags(self):
        if self['flags'] is None:
            return

        print 'NTLM Flags: {0:032b}'.format(self['flags'])
        if self['flags'] & NegotiateFlag.NTLMSSP_UNICODE:
            print "NTLMSSP_UNICODE (Negotiate Unicode)"
        if self['flags'] & NegotiateFlag.NTLMSSP_OEM:
            print "NTLMSSP_OEM (Negotiate OEM)"
        if self['flags'] & NegotiateFlag.NTLMSSP_TARGET:
            print "NTLMSSP_TARGET (Request Target)"
        if self['flags'] & NegotiateFlag.NTLMSSP_SIGN:
            print "NTLMSSP_SIGN (Negotiate Sign)"
        if self['flags'] & NegotiateFlag.NTLMSSP_SEAL:
            print "NTLMSSP_SEAL (Negotiate Seal)"
        if self['flags'] & NegotiateFlag.NTLMSSP_DATAGRAM:
            print "NTLMSSP_DATAGRAM (Negotiate Datagram Style)"
        if self['flags'] & NegotiateFlag.NTLMSSP_LM_KEY:
            print "NTLMSSP_LM_KEY (Negotiate Lan Manager Key)"
        if self['flags'] & NegotiateFlag.NTLMSSP_NETWARE:
            print "NTLMSSP_NETWARE (Negotiate Netware)"
        if self['flags'] & NegotiateFlag.NTLMSSP_NTLM_KEY:
            print "NTLMSSP_NTLM_KEY (Negotiate NTLM Key)"
        if self['flags'] & NegotiateFlag.NTLMSSP_ANONYMOUS:
            print "NTLMSSP_ANONYMOUS (Anonymous Context)"
        if self['flags'] & NegotiateFlag.NTLMSSP_DOMAIN:
            print "NTLMSSP_DOMAIN (Domain Supplied)"
        if self['flags'] & NegotiateFlag.NTLMSSP_WORKSTATION:
            print "NTLMSSP_WORKSTATION (Workstation Supplied)"
        if self['flags'] & NegotiateFlag.NTLMSSP_LOCAL_CALL:
            print "NTLMSSP_LOCAL_CALL (Local Call)"
        if self['flags'] & NegotiateFlag.NTLMSSP_ALWAYS_SIGN:
            print "NTLMSSP_ALWAYS_SIGN (Always Sign)"
        if self['flags'] & NegotiateFlag.NTLMSSP_TARGET_TYPE_DOMAIN:
            print "NTLMSSP_TARGET_TYPE_DOMAIN ()"
        if self['flags'] & NegotiateFlag.NTLMSSP_TARGET_TYPE_SERVER:
            print "NTLMSSP_TARGET_TYPE_SERVER ()"
        if self['flags'] & NegotiateFlag.NTLMSSP_TARGET_TYPE_SHARE:
            print "NTLMSSP_TARGET_TYPE_SHARE ()"
        if self['flags'] & NegotiateFlag.NTLMSSP_NTLM2_KEY:
            print "NTLMSSP_NTLM2_KEY (NTLM2 used signing and sealing)"
        if self['flags'] & NegotiateFlag.NTLMSSP_TARGET_INFO:
            print "NTLMSSP_TARGET_INFO (Negotiate Target Info)"
        if self['flags'] & NegotiateFlag.NTLMSSP_VERSION:
            print "NTLMSSP_VERSION (Version)"
        if self['flags'] & NegotiateFlag.NTLMSSP_KEY_128:
            print "NTLMSSP_KEY_128 (Negotiate 128)"
        if self['flags'] & NegotiateFlag.NTLMSSP_KEY_EXCHANGE:
            print "NTLMSSP_KEY_EXCHANGE (Negotiate Key Exchange)"
        if self['flags'] & NegotiateFlag.NTLMSSP_NEGOTIATE_56:
            print "NTLMSSP_NEGOTIATE_56 (Negotiate 56)"

class TargetInfo(object):
    NTLMSSP_AV_EOL              = 0x00
    NTLMSSP_AV_HOSTNAME         = 0x01
    NTLMSSP_AV_DOMAINNAME       = 0x02
    NTLMSSP_AV_DNS_HOSTNAME     = 0x03
    NTLMSSP_AV_DNS_DOMAINNAME   = 0x04
    NTLMSSP_AV_DNS_TREENAME     = 0x05
    NTLMSSP_AV_FLAGS            = 0x06
    NTLMSSP_AV_TIME             = 0x07
    NTLMSSP_AV_RESTRICTIONS     = 0x08
    NTLMSSP_AV_TARGET_NAME      = 0x09
    NTLMSSP_AV_CHANNEL_BINDINGS = 0x0a

    def __init__(self, data=None):
        self.fields = OrderedDict()
        if data is not None:
            self.from_string(data)

    def __setitem__(self, key, value):
        self.fields[key] = (len(value), value)

    def __getitem__(self, key):
        if self.fields.has_key(key):
           return self.fields[key]
        return None

    def __delitem__(self, key):
        del self.fields[key]

    def __len__(self):
        return len(self.get_data())

    def __str__(self):
        return self.get_data()

    def from_string(self, data):
        attribute_type = 0xff
        while attribute_type is not TargetInfo.NTLMSSP_AV_EOL:
            # Parse the Attribute Value pair from the structure
            attribute_type = struct.unpack('<H', data[:struct.calcsize('<H')])[0]
            data = data[struct.calcsize('<H'):]
            length = struct.unpack('<H', data[:struct.calcsize('<H')])[0]
            data = data[struct.calcsize('<H'):]
            # Add a new field to the object for the parse attribute value
            self.fields[attribute_type] = (length, data[:length])
            data = data[length:]

    def dump(self):
        for i in self.fields.keys():
            print "%s: {%r}" % (i, self[i])

    def get_data(self):
        if self.fields.has_key(TargetInfo.NTLMSSP_AV_EOL):
            del self.fields[TargetInfo.NTLMSSP_AV_EOL]

        data = ''
        for i in self.fields.keys():
            data += struct.pack('<HH', i, self[i][0])
            data += self[i][1]

        # end with a NTLMSSP_AV_EOL
        data += struct.pack('<HH', TargetInfo.NTLMSSP_AV_EOL, 0)
        return data


class Version(object):
    """
    ====================================================================================================================
    Tokens generated on Windows XP and later usually include Version information, we will include this information for
    debugging and completeness. The version number will be based on a standard Windows 10 version token
    ====================================================================================================================
    """
    def get_os_version(self):
        if len(self['os_version']) == 0:
            return None
        else:
            major = struct.unpack('B', self['os_version'][0])[0]
            minor = struct.unpack('B', self['os_version'][1])[0]
            build = struct.unpack('H', self['os_version'][2:4])[0]
            return major, minor, build


class Negotiate(Structure, Version, Message):
    """
    ====================================================================================================================
    Represents an NTLM Negotiate Message
    ====================================================================================================================
    """
    structure = (
        ('', '"NTLMSSP\x00'),
        ('message_type', '<L=1'),
        ('flags', '<L'),
        ('domain_len', '<H-domain_name'),
        ('domain_max_len', '<H-domain_name'),
        ('domain_offset', '<L=0'),
        ('host_len', '<H-host_name'),
        ('host_maxlen', '<H-host_name'),
        ('host_offset', '<L=0'),
        ('os_version', ':'),
        ('domain_name', ':'),
        ('host_name', ':'))

    def __init__(self, flags=NegotiateFlag.NTLMSSP_NTLM_KEY, domain='', host=''):
        """
        Initializes a new NTLM Type 1 Message. This implementation always requires UNICODE. Users should avoid setting
        the legacy OEM and LM_KEY Flags unless they provide an implementation.
        """
        Structure.__init__(self)
        flags |= NegotiateFlag.NTLMSSP_UNICODE
        self['flags'] = flags
        self['domain_name'] = domain
        self['host_name'] = host
        self['os_version'] = ''

    def get_domain(self):
        return self['domain_name']

    def get_host(self):
        return self['host_name']

    def get_data(self):
        if len(self.fields['domain_name']) > 0:
            self['flags'] |= NegotiateFlag.NTLMSSP_DOMAIN
        if len(self.fields['host_name']) > 0:
            self['flags'] |= NegotiateFlag.NTLMSSP_WORKSTATION
        if len(self.fields['os_version']) > 0:
            self['flags'] |= NegotiateFlag.NTLMSSP_VERSION
        if (self['flags'] & NegotiateFlag.NTLMSSP_VERSION) == NegotiateFlag.NTLMSSP_VERSION:
            version_len = 8
        else:
            version_len = 0
        if (self['flags'] & NegotiateFlag.NTLMSSP_WORKSTATION) == NegotiateFlag.NTLMSSP_WORKSTATION:
            self['domain_offset'] = 32 + version_len
        if (self['flags'] & NegotiateFlag.NTLMSSP_DOMAIN) == NegotiateFlag.NTLMSSP_DOMAIN:
            self['host_offset'] = 32 + len(self['domain_name']) + version_len
        return Structure.get_data(self)

    def from_string(self, data):
        Structure.from_string(self, data)
        # Just in case there's more data after the TargetInfoFields
         # self['TargetInfoFields'] = self['TargetInfoFields'][:self['TargetInfoFields_len']]
        # We gotta process the TargetInfoFields
        #if self['TargetInfoFields_len'] > 0:
        #    av_pairs = AV_PAIRS(self['TargetInfoFields'][:self['TargetInfoFields_len']])
        #    self['TargetInfoFields'] = av_pairs

        return self

class Challenge(Structure, Version, Message):
    """
    ====================================================================================================================
    Represents an NTLM Type 2 (Challenge) Message
    ====================================================================================================================
    """
    structure = (
        ('', '"NTLMSSP\x00'),
        ('message_type', '<L=2'),
        ('target_name_len', '<H-target_name'),
        ('target_name_max', '<H-target_name'),
        ('target_name_offset', '<L=40'),
        ('flags', '<L=0'),
        ('challenge', '8s'),
        ('reserved', '8s=""'),
        # Windows 9x and NT4 omit the following optional fields, they are
        # parsed based only on the flags bitfield
        ('target_info_fields_len', ':'),
        ('target_info_fields_max', ':'),
        ('target_info_fields_offset', ':'),
        ('os_version', ':'),
        ('target_name', ':'),
        ('target_info_fields', ':'))

    def __init__(self):
        Structure.__init__(self)
        self['os_version'] = ''

    @staticmethod
    def check_version(flags):
        if flags is not None and flags & NegotiateFlag.NTLMSSP_VERSION == 0:
            return 0
        else:
            return 8

    def get_data(self):
        if len(self.fields['os_version']) > 0:
            self['flags'] |= NegotiateFlag.NTLMSSP_VERSION
        if (self['flags'] & NegotiateFlag.NTLMSSP_VERSION) == NegotiateFlag.NTLMSSP_VERSION:
            version_len = 8
        else:
            version_len = 0
        if self['target_info_fields'] is not None and type(self['target_info_fields']) is not str:
            raw_av_fields = self['target_info_fields'].getData()
            self['target_info_fields'] = raw_av_fields
        return Structure.get_data(self)

    def from_string(self, data):
        Structure.from_string(self, data)

        if self['flags'] & NegotiateFlag.NTLMSSP_TARGET:
            target_name_offset = self['target_name_offset']
            target_name_end = self['target_name_len'] + target_name_offset
            target_name = data[target_name_offset:target_name_end]
        else:
            target_name = ''

        if self['flags'] & NegotiateFlag.NTLMSSP_VERSION:
            version = data[48:56]
        else:
            version = ''

        if self['flags'] & NegotiateFlag.NTLMSSP_TARGET_INFO:
            target_info_fields_len = struct.unpack('<H', data[40:42])[0]
            target_info_fields_offset = struct.unpack('<L', data[44:48])[0]
            target_info_fields_end = target_info_fields_offset + target_info_fields_len
            target_info = TargetInfo(data[target_info_fields_offset:target_info_fields_end])
        else:
            target_info = None

        self['target_name'] = target_name
        self['os_version'] = version
        self['target_info_fields'] = target_info
        return self


class ChallengeResponse(Structure, Version, Message):
    """
    ====================================================================================================================
    Represents an NTLM Type 3 (Challenge Response) Message

    challenge = ''

    ====================================================================================================================
    """
    structure = (
        ('','"NTLMSSP\x00'),
        ('message_type','<L=3'),
        ('lanman_len','<H-lanman'),
        ('lanman_max_len','<H-lanman'),
        ('lanman_offset','<L'),
        ('ntlm_len','<H-ntlm'),
        ('ntlm_max_len','<H-ntlm'),
        ('ntlm_offset','<L'),
        ('domain_len','<H-domain_name'),
        ('domain_max_len','<H-domain_name'),
        ('domain_offset','<L'),
        ('user_len','<H-user_name'),
        ('user_max_len','<H-user_name'),
        ('user_offset','<L'),
        ('host_len','<H-host_name'),
        ('host_max_len','<H-host_name'),
        ('host_offset','<L'),
        ('session_key_len','<H-session_key'),
        ('session_key_max_len','<H-session_key'),
        ('session_key_offset','<L'),
        ('flags','<L'),
        ('VersionLen','_-Version','self.check_version(self["flags"])'),
        ('version',':=""'),
        ('MICLen','_-MIC'),
        ('mic',':=""'),
        ('domain_name',':'),
        ('user_name',':'),
        ('host_name',':'),
        ('lanman',':'),
        ('ntlm',':'),
        ('session_key',':'))

    def __init__(self, flags, lm_response, nt_response, domain, username, session_key=None, host_name=None):
        Structure.__init__(self)
        self['flags'] = flags
        self['lanman'] = lm_response
        self['ntlm'] = nt_response
        self['domain_name'] = domain.encode('utf-16le')
        self['user_name'] = username.encode('utf-16le')
        self['host_name'] = ''
        self['version'] = ''
        self['mic'] = ''
        self['session_key'] = session_key

    def check_version(self, flags):
        if flags is not None:
           if flags & NegotiateFlag.NTLMSSP_VERSION == 0:
              return 0
        return 8

    def get_data(self):
        if len(self.fields['host_name']) > 0:
            self['flags'] |= NegotiateFlag.NTLMSSP_WORKSTATION
        if len(self.fields['domain_name']) > 0:
            self['flags'] |= NegotiateFlag.NTLMSSP_DOMAIN
        #if len(self.fields['os_version']) > 0:
        #    self['flags'] |= NegotiateFlag.NTLMSSP_VERSION
        #if (self['flags'] & NegotiateFlag.NTLMSSP_VERSION) == NegotiateFlag.NTLMSSP_VERSION:
        #    version_len = 8
        #else:
         #   version_len = 0
        self['domain_offset'] = 64 + len(self['mic']) + len(self['version'])
        self['user_offset'] = self['domain_offset'] + len(self['domain_name'])
        self['host_offset'] = self['user_offset'] + len(self['user_name'])
        self['lanman_offset'] = self['host_offset'] + len(self['host_name'])
        self['ntlm_offset'] = self['lanman_offset'] + len(self['lanman'])
        self['session_key_offset'] = self['ntlm_offset'] + len(self['ntlm'])
        return Structure.get_data(self)

    def from_string(self, data):
        Structure.from_string(self, data)
        # [MS-NLMP] page 27
        # Payload data can be present in any order within the Payload field,
        # with variable-length padding before or after the data

        domain_offset = self['domain_offset']
        domain_end = self['domain_len'] + domain_offset
        self['domain_name'] = data[domain_offset:domain_end]

        host_offset = self['host_offset']
        host_end    = self['host_len'] + host_offset
        self['host_name'] = data[host_offset:host_end]

        user_offset = self['user_offset']
        user_end    = self['user_len'] + user_offset
        self['user_name'] = data[user_offset:user_end]

        ntlm_offset = self['ntlm_offset']
        ntlm_end    = self['ntlm_len'] + ntlm_offset
        self['ntlm'] = data[ntlm_offset:ntlm_end]

        lanman_offset = self['lanman_offset']
        lanman_end    = self['lanman_len'] + lanman_offset
        self['lanman'] = data[lanman_offset:lanman_end]

        #if len(data) >= 36:
        #    self['os_version'] = data[32:36]
        #else:
        #    self['os_version'] = ''