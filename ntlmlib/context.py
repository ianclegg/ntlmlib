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

import os
import struct
import logging

from socket import gethostname
from Crypto.Hash import HMAC
from Crypto.Cipher import ARC4

from ntlmlib.messages import Negotiate
from ntlmlib.messages import Challenge
from ntlmlib.messages import ChallengeResponse
from ntlmlib.messages import TargetInfo
from ntlmlib.security import Ntlm2Sealing
from ntlmlib.constants import NegotiateFlag

logger = logging.getLogger(__name__)

"""
TODO!!
There is some inconsistency in the design between the context and the authenticator that needs to be addressed.
when session security is used we need to know get session key and get the key exchange key - but this is not
sensible with the current design.
the session key and the keyex key depend on the negotiate flags, the challenge response and the server key.

we need to know the session key and keyex key.
get_session_key(flags, )
get_key_exchange_key()

"""
class NtlmContext(object):
    """
    For initiating NTLM authentication (including NTLMv2). If you want to add NTLMv2 authentication support to something
    this is what you want to use. See the code for details.
    """
    def __init__(self, authenticator, session_security='none', **kwargs):
        if session_security not in ('none', 'sign', 'encrypt'):
            raise Exception("session_security must be none, sign or encrypt")

        # Initialise a random default 8 byte NTLM client challenge
        self._os_version = kwargs.get('version', (6, 6, 0))

        # TODO, should accept a list of possible in order of preference
        # these should probably be 'integrity' and 'confidentiality'
        # encrypt, sign, none would not raise an error

        # TODO, we should set the negotiate flags based on the lm level :-s
        # Note, this still works with 9x and N4.0 though
        self.flags = NegotiateFlag.NTLMSSP_TARGET |\
                     NegotiateFlag.NTLMSSP_TARGET_INFO |\
                     NegotiateFlag.NTLMSSP_KEY_128


        if session_security == 'sign':
            self.flags |= NegotiateFlag.NTLMSSP_KEY_EXCHANGE |\
                          NegotiateFlag.NTLMSSP_ALWAYS_SIGN |\
                          NegotiateFlag.NTLMSSP_SIGN |\
                          NegotiateFlag.NTLMSSP_NTLM2_KEY

        if session_security == 'encrypt':
            self.flags |= NegotiateFlag.NTLMSSP_KEY_EXCHANGE |\
                          NegotiateFlag.NTLMSSP_ALWAYS_SIGN |\
                          NegotiateFlag.NTLMSSP_SIGN  |\
                          NegotiateFlag.NTLMSSP_SEAL |\
                          NegotiateFlag.NTLMSSP_NTLM2_KEY

        self._wrapper = None
        self._session_key = None
        self._authenticator = authenticator
        self._session_security = session_security
        self.is_established = False

    def is_established(self):
        return self.is_established

    def initialize_security_context(self):
        """
        Idiomatic Python implementation of initialize_security_context, implemented as a generator function using
        yield to both accept incoming and return outgoing authentication tokens
        :return: The response to be returned to the server
        """
        # Generate the NTLM Negotiate Request
        negotiate_token = self._negotiate(self.flags)
        challenge_token = yield negotiate_token

        # Generate the Authenticate Response
        authenticate_token = self._challenge_response(negotiate_token, challenge_token)
        yield authenticate_token

    def wrap_message(self, message):
        """
        Cryptographically signs and optionally encrypts the supplied message. The message is only encrypted if
        'confidentiality' was negotiated, otherwise the message is left untouched.
        :return: A tuple containing the message signature and the optionally encrypted message
        """
        if not self.is_established:
            raise Exception("Context has not been established")
        if self._wrapper is None:
            raise Exception("Neither sealing or signing have been negotiated")
        else:
            return self._wrapper.wrap(message)


    def unwrap_message(self, message, signature):
        # TODO implement signature exceptions and document
        """
        Verifies the supplied signature against the message and decrypts the message if 'confidentiality' was
        negotiated.
        A SignatureException is raised if the signature cannot be parsed or the version is unsupported
        A SequenceException is raised if the sequence number in the signature is incorrect
        A ChecksumException is raised if the in the signature checksum is invalid
        :return: The decrypted message
        """
        if not self.is_established:
            raise Exception("Context has not been established")
        if self._wrapper is None:
            raise Exception("Neither sealing or signing have been negotiated")
        else:
            return self._wrapper.unwrap(message, signature)

    def _negotiate(self, flags):
        # returns the response
        return Negotiate(flags, self._authenticator.get_domain(), gethostname()).get_data()

    def hack(self, flags, session):
        self._wrapper = Ntlm2Sealing(flags, session)

    def _challenge_response(self, negotiate_token, challenge_token):
        challenge = Challenge()
        challenge.from_string(challenge_token)
        flags = challenge['flags']
        nonce = challenge['challenge']
        challenge_target = challenge['target_info_fields']

        # Compute the ntlm response; this depends on an interplay between the ntlm challenge flags and the settings
        # used to construct the 'authenticator' object
        ntlm_response, session_key, target_info = self._authenticator.get_ntlm_response(flags, nonce, challenge_target)

        # [MS-NLMP] v20140502 NT LAN Manager (NTLM) Authentication Protocol (Page 46)
        # If NTLM v2 authentication is used and the CHALLENGE_MESSAGE contains a TargetInfo field, the client SHOULD
        # NOT send the LmChallengeResponse and SHOULD set the LmChallengeResponseLen and LmChallengeResponseMaxLen
        if challenge_target is None and target_info is None:
            lm_response = ''
        else:
            lm_response, session_key = self._authenticator.get_lm_response(flags, nonce)

        # [MS-NLMP] v20140502 NT LAN Manager (NTLM) Authentication Protocol (Page 46)
        # If the we negotiated key exchange, generate a new new master key for the session, this is RC4-encrypted
        # with the previously selected session key.
        # "This capability SHOULD be used because it improves security for message integrity or confidentiality"
        if flags & NegotiateFlag.NTLMSSP_KEY_EXCHANGE:
            cipher = ARC4.new(session_key)
            exported_session_key = cipher.encrypt(os.urandom(16))
        else:
            exported_session_key = session_key

        # Ensure the negotiated flags guarantee at least the minimum level of session security required by the
        # client when the context was constructed
        if 'encrypt' in self._session_security and not flags & NegotiateFlag.NTLMSSP_SEAL:
            raise Exception("failed to negotiate session encryption")

        if 'sign' in self._session_security and not flags & NegotiateFlag.NTLMSSP_SIGN:
            raise Exception("failed to negotiate session encryption")

        authenticate = ChallengeResponse(flags, lm_response, ntlm_response,
                                         self._authenticator.get_domain(), self._authenticator.get_username(),
                                         exported_session_key)

        # If the authenticate response has the MIC flag set, we must calculate and set the mic field the 'authenticator'
        # object determines when mic code generation is required and sets this flag
        if _mic_required(target_info):
            _add_mic(authenticate, session_key, negotiate_token, challenge_token)

        # If session security was negotiated we should construct an appropriate object to perform the subsequent
        # message wrapping and unwrapping

        # We need a factory which will construct the correct wrapper based on the flags, it needs to support
        # NTLM1 and NTLM2 Session Security. This is tricky, because it needs the correct key based on flags
        # for NTLM1, 'Negotiate Lan Manager Key' determines if we need a User Session Key or Lan Manager Session Key
        # this needs to be done in advance by whatever computes the master key and key exchange key
        #
        if flags & NegotiateFlag.NTLMSSP_SEAL:
            self._wrapper = Ntlm2Sealing(flags, session_key)
        elif flags & NegotiateFlag.NTLMSSP_SIGN:
            self._wrapper = Ntlm2Signing(flags, session_key)

        # TODO: Check the returned flags are set correctly
        #if flags & NegotiateFlag.NTLMSSP_VERSION:
        #    flags &= 0xffffffff ^ NegotiateFlag.NTLMSSP_VERSION
        #if flags & NegotiateFlag.NTLMSSP_NTLM_KEY:
        #   flags &= 0xffffffff ^ NegotiateFlag.NTLMSSP_NTLM_KEY

        self.is_established = True
        self.flags = flags

        return authenticate.get_data()

def _mic_required(target_info):
    """
    Checks the MsvAvFlags field of the supplied TargetInfo structure to determine in the MIC flags is set
    :param target_info: The TargetInfo structure to check
    :return: a boolean value indicating that the MIC flag is set
    """
    if target_info is not None and target_info[TargetInfo.NTLMSSP_AV_FLAGS] is not None:
        flags = struct.unpack('<I', target_info[TargetInfo.NTLMSSP_AV_FLAGS][1])[0]
        return bool(flags & 0x00000002)

def _add_mic(authenticate, session_key, negotiate_token, challenge_token):
    """

    :param authenticate:
    :param session_key:
    :param negotiate_token:
    :param challenge_token:
    :return:
    """
    # before computing the MIC, the version field must be preset and the MIC
    # field must be zeroed out of the authenticate message.
    authenticate['mic'] = '\x00' * 16
    authenticate['version'] = '\x06\x01\xb1\x1d\x00\x00\x00\x0f'
    authenticate_token = authenticate.get_data()

    # compute the MIC
    mic = HMAC.new(session_key)
    mic.update(negotiate_token)
    mic.update(challenge_token)
    mic.update(authenticate_token)

    # set the MIC
    authenticate['mic'] = mic.digest()

