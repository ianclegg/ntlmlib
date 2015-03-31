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
import hashlib
import zlib
import hmac
from Crypto.Cipher import ARC4

from ntlmlib.constants import NegotiateFlag
from ntlmlib.structure import Structure

class _Ntlm2MessageSignature(Structure):
    structure = (
        ('version', '<L=1'),
        ('checksum', '<q'),
        ('sequence', '<i'),
    )

    def __init__(self):
        Structure.__init__(self)

class _Ntlm1MessageSignature(Structure):
    structure = (
        ('version', '<L=1'),
        ('random', ':'),
        ('checksum', ':'),
        ('sequence', ':'),
    )

    def __init__(self):
        Structure.__init__(self)

    def from_string(self, data):
        Structure.__init__(self)
        self['random'] = data[4:8]
        self['checksum'] = data[8:12]
        self['sequence'] = data[12:16]


class _Ntlm1Session(object):
    """
      _  _ _____ _    __  __   _
     | \| |_   _| |  |  \/  | / |   SESSION SECURITY
     | .` | | | | |__| |\/| | | |    MSDOS, Windows 3.11 and Later
     |_|\_| |_| |____|_|  |_| |_|

    This is only used by very old downlevel clients, including MS-DOS, Windows 3.11 and early builds of Windows 95
    and Windows NT 4. NTLM1 session security offers little protection against modern cryptographic attacks and may
    lead password compromise. NTLM2 sesion security, which can still be used with NTLMv1 authentication, offers
    significantly enchanced security. NTLM1 Session Security is only used if the server doesnt set NTLMSSP_NTLM2_KEY
    """
    def __init__(self, flags, session_key):
        self._key = _Ntlm1Session._weaken_key(flags, session_key)
        self._seal = ARC4.new(self._key)
        self._sequence = 0

    @staticmethod
    def _weaken_key(flags, key):
        # If Lan Manager Session Key computation was not negotiated then we must be using the LM and NTLM
        # User keys. These user keys are tied to the password hash and remain the same across sessions.
        # Since they are so weak (the U.S. NSA) probably decided they don't need to be weakened anymore
        if not flags & NegotiateFlag.NTLMSSP_LM_KEY:
            return key
        # The Lan Manager Session Key is computed for each session, the full 128bit keyspace is never used
        # If the 56bit flag is set the key is reduced to 56bits, otherwise it is 40bits with magic bytes appended
        if flags & NegotiateFlag.NTLMSSP_KEY_128:
            raise Exception('NTLM1 Session Security does not support 128bit keys')
        if flags & NegotiateFlag.NTLMSSP_NEGOTIATE_56:
            return key[:7] + '\xa0'
        else:
            return key[:5] + '\xe5\x38\xb0'

    def sign(self, message):
        # NTLM1 integrity checks use a simple CRC in little endian format, the CRC and Sequence are both
        # encrypted using the weakened session key or user key
        crc = zlib.crc32(message)
        mac = _Ntlm1MessageSignature()

        mac['random'] = self._seal.encrypt(struct.pack('<i', 0))
        mac['checksum'] = self._seal.encrypt(struct.pack('<i', crc))
        mac['sequence'] = self._seal.encrypt(struct.pack('<i', self._sequence))

        # [MS-NLMP] v20140502 NT LAN Manager (NTLM) Authentication Protocol (Page 64)
        # Once all fields have been encrypted with the RC4 keystream the random pad is overwritten
        # with 4 zero bytes (some implementations use a pseudo random sequence instead)
        mac['random'] = struct.pack('<i', 0)

        # Increment the sequence number after each signature is computed
        self._sequence += 1
        return str(mac)

    def verify(self, message, signature):
        # Parse the signature header
        mac = _Ntlm1MessageSignature()
        mac.from_string(signature)

        # decrypt and then unpack the signature fields in order
        self._seal.decrypt(mac['random'])
        crc = struct.unpack('<i', self._seal.decrypt(mac['checksum']))[0]
        sequence = struct.unpack('<i', self._seal.decrypt(mac['sequence']))[0]

        # validate the sequence number is what we expect
        if sequence != self._sequence:
            raise Exception("The message was not received in the correct sequence.")

        # validate the supplied checksum matches our computed checksum
        if crc != zlib.crc32(message):
            raise Exception("The message has been altered")

        # once more, ensure the sequence number is incremented
        self._sequence += 1

    def encrypt(self, message):
        """
        Encrypts the supplied message using NTLM1 Session Security
        :param message: The message to be encrypted
        :return: The signed and encrypted message
        """
        return self._seal.encrypt(message)

    def decrypt(self, message):
        """
        Decrypts the supplied message using NTLM1 Session Security
        :param message: The ciphertext to be decrypted
        :return: The original plaintext
        """
        return self._seal.decrypt(message)

class Ntlm1Signing(_Ntlm1Session):
    def __init__(self, flags, session_key):
        _Ntlm1Session.__init__(self, flags, session_key)

    def wrap(self, message):
        return _Ntlm1Session.sign(self, message)

    def unwrap(self, message):
        return _Ntlm1Session.verify(self, message)

class Ntlm1Sealing(_Ntlm1Session):
    """

    """
    def __init__(self, flags, session_key):
        _Ntlm1Session.__init__(self, flags, session_key)

    def wrap(self, message):
        """
        NTM GSSwrap()
        :param message: The message to be encrypted
        :return: The signed and encrypted message
        """
        cipher_text = _Ntlm1Session.encrypt(self, message)
        signature = _Ntlm1Session.sign(self, message)
        return cipher_text, signature

    def unwrap(self, message, signature):
        """
        NTLM GSSUnwrap()
        :param message: The message to be encrypted
        :return: The signed and encrypted message
        """
        plain_text = _Ntlm1Session.decrypt(self, message)
        _Ntlm1Session.verify(self, plain_text, signature)
        return plain_text


class _Ntlm2Session(object):
    """
      _  _ _____ _    __  __   ___
     | \| |_   _| |  |  \/  | |_  )   SESSION SECURITY
     | .` | | | | |__| |\/| |  / /     Windows NT4 SP4 and later
     |_|\_| |_| |____|_|  |_| /___|

    This is a newer scheme which can be used with both NTLMv1 and NTLMv2 Authentication.
    """
    client_signing = "session key to client-to-server signing key magic constant\x00"
    client_sealing = "session key to client-to-server sealing key magic constant\x00"
    server_signing = "session key to server-to-client signing key magic constant\x00"
    server_sealing = "session key to server-to-client sealing key magic constant\x00"

    def __init__(self, flags, session_key):
        self.key_exchange = True
        self.client_sequence = 0
        self.server_sequence = 0
        session_key = _Ntlm2Session._weaken_key(flags, session_key)
        self.client_signing_key = _Ntlm2Session._generate_key(session_key + _Ntlm2Session.client_signing)
        self.server_signing_key = _Ntlm2Session._generate_key(session_key + _Ntlm2Session.server_signing)

        client_sealing_key = _Ntlm2Session._generate_key(session_key + _Ntlm2Session.client_sealing)
        server_sealing_key = _Ntlm2Session._generate_key(session_key + _Ntlm2Session.server_sealing)
        self.client_seal = ARC4.new(client_sealing_key)
        self.server_seal = ARC4.new(server_sealing_key)

    @staticmethod
    def _generate_key(material):
        md5 = hashlib.new('md5')
        md5.update(material)
        return md5.digest()

    @staticmethod
    def _weaken_key(flags, key):
        """
        NOTE: Key weakening in NTLM2 (Extended Session Security) is performed simply by truncating the master key (or
        secondary master key, if key exchange is performed) to the appropriate length. 128-bit keys are supported under
        NTLM2. In this case, the master key is used directly in the generation of subkeys (with no weakening performed).
        :param flags: The negotiated NTLM flags
        :return: The 16-byte key to be used to sign messages
        """
        if flags & NegotiateFlag.NTLMSSP_KEY_128:
            return key
        if flags & NegotiateFlag.NTLMSSP_NEGOTIATE_56:
            return key[:7]
        else:
            return key[:5]

    def sign(self, message):
        """
        Generates a signature for the supplied message using NTLM2 Session Security
        Note: [MS-NLMP] Section 3.4.4
        The message signature for NTLM with extended session security is a 16-byte value that contains the following
        components, as described by the NTLMSSP_MESSAGE_SIGNATURE structure:
         - A 4-byte version-number value that is set to 1
         - The first eight bytes of the message's HMAC_MD5
         - The 4-byte sequence number (SeqNum)
        :param message: The message to be signed
        :return: The signature for supplied message
        """
        hmac_context = hmac.new(self.client_signing_key)
        hmac_context.update(struct.pack('<i', self.client_sequence) + message)

        # If a key exchange key is negotiated the first 8 bytes of the HMAC MD5 are encrypted with RC4
        if self.key_exchange:
            checksum = self.client_seal.encrypt(hmac_context.digest()[:8])
        else:
            checksum = hmac_context.digest()[:8]

        mac = _Ntlm2MessageSignature()
        mac['checksum'] = struct.unpack('<q', checksum)[0]
        mac['sequence'] = self.client_sequence

        # Increment the sequence number after signing each message
        self.client_sequence += 1
        return str(mac)

    def verify(self, message, signature):
        """
        Verified the signature attached to the supplied message using NTLM2 Session Security
        :param message: The message whose signature will verified
        :return: True if the signature is valid, otherwise False
        """
        # Parse the signature header
        mac = _Ntlm2MessageSignature()
        mac.from_string(signature)

        # validate the sequence
        if mac['sequence'] != self.server_sequence:
            raise Exception("The message was not received in the correct sequence.")

        # extract the supplied checksum
        checksum = struct.pack('<q', mac['checksum'])
        if self.key_exchange:
            checksum = self.server_seal.decrypt(checksum)

        # calculate the expected checksum for the message
        hmac_context = hmac.new(self.server_signing_key)
        hmac_context.update(struct.pack('<i', self.server_sequence) + message)
        expected_checksum = hmac_context.digest()[:8]

        # validate the supplied checksum is correct
        if checksum != expected_checksum:
            raise Exception("The message has been altered")

        self.server_sequence += 1

    def encrypt(self, message):
        """
        Encrypts the supplied message using NTLM2 Session Security
        :param message: The message to be encrypted
        :return: The signed and encrypted message
        """
        return self.client_seal.encrypt(message)

    def decrypt(self, cipher_text):
        """
        Decrypts the supplied message using NTLM2 Session Security
        :param message: The ciphertext to be decrypted
        :return: The original plaintext
        """
        return self.server_seal.decrypt(cipher_text)


class Ntlm2Signing(_Ntlm2Session):
    def __init__(self, flags, session_key):
        _Ntlm2Session.__init__(self, flags, session_key)

    def wrap(self, message):
        return _Ntlm2Session.sign(self, message)

    def unwrap(self, message):
        return _Ntlm2Session.verify(self, message)


class Ntlm2Sealing(_Ntlm2Session):
    """

    """
    def __init__(self, flags, session_key):
        _Ntlm2Session.__init__(self, flags, session_key)

    def wrap(self, message):
        """
        NTM GSSwrap()
        :param message: The message to be encrypted
        :return: The signed and encrypted message
        """
        cipher_text = _Ntlm2Session.encrypt(self, message)
        signature = _Ntlm2Session.sign(self, message)
        return cipher_text, signature

    def unwrap(self, message, signature):
        """
        NTLM GSSUnwrap()
        :param message: The message to be encrypted
        :return: The signed and encrypted message
        """
        plain_text = _Ntlm2Session.decrypt(self, message)
        _Ntlm2Session.verify(self, plain_text, signature)
        return plain_text
