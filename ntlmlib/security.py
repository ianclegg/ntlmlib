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
import hmac
from Crypto.Cipher import ARC4

from ntlmlib.constants import NegotiateFlag
from ntlmlib.structure import Structure


client_signing = "session key to client-to-server signing key magic constant\x00"
client_sealing = "session key to client-to-server sealing key magic constant\x00"
server_signing = "session key to server-to-client signing key magic constant\x00"
server_sealing = "session key to server-to-client sealing key magic constant\x00"


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
        ('random', '<i=0'),
        ('checksum', '<i'),
        ('sequence', '<i'),
    )

    def __init__(self):
        Structure.__init__(self)

"""
class _Ntlm1Session(object):
    def __init__(self, flags, session_key):
        self.signing_key = _Ntlm1Session._weaken_key(flags, session_key)

    @staticmethod
    def _weaken_key(flags, key):
        if flags & NegotiateFlag.NTLMSSP_LM_KEY:
            if flags & NegotiateFlag.NTLMSSP_NEGOTIATE_56:
                return key[:7] + '\xa0'
            else:
                return key[:5] + '\xe5\x38\xb0'
        return key

    def sign(self, message):
        pass

    def verify(self, message):
        pass

    def seal(self, message):
        pass

    def unseal(self, message):
        pass



    def get_signing_key(self, flags, key):

        Returns the key to be used for signing messages. Under NTLM2 messages
        are signed with the 128-bit master key. Messages are signed with the
        weakened key under NTLM1
        :param flags: The NTLM Negotiate flags
        :return: The 16-byte key to be used to sign messages


        # NTLM2 session security requires the generation of
        if not (flags & NegotiateFlag.NTLMSSP_NTLM2_KEY):
            return signing_key
        else:
            signing_key += SessionSecurity.SIGNING_CLIENT
"""


class _Ntlm2Session(object):
    """
    Implements NTLM2 Session Security
    This is a newer scheme which can be used with both NTLMv1 and NTLMv2 Authentication
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
        self.client_signing_key = _Ntlm2Session._generate_key(session_key + client_signing)
        self.server_signing_key = _Ntlm2Session._generate_key(session_key + server_signing)

        client_sealing_key = _Ntlm2Session._generate_key(session_key + client_sealing)
        server_sealing_key = _Ntlm2Session._generate_key(session_key + server_sealing)
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
        mac['version'] = 1
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
