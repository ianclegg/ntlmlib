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

from socket import gethostname

from ntlmlib.messages import Negotiate
from ntlmlib.messages import Challenge
from ntlmlib.messages import ChallengeResponse
from ntlmlib.security import Ntlm2Sealing
from ntlmlib.constants import NegotiateFlag


class NtlmContext(object):
    """
    For initiating NTLM authentication (including NTLMv2). If you want to add NTLMv2 authentication support to something
    this is what you want to use. See the code for details.
    """
    def __init__(self, authenticator, session_security='none', **kwargs):
        if session_security not in ('none', 'sign', 'encrypt'):
            raise Exception("session_security must be none, sign or encrypt")

        # TODO, should accept a list of possible in order of preference
        #   encrypt, sign, none would not raise an error

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
        challenge_data = yield self._negotiate(self.flags).get_data()

        # De-serialize the challenge
        challenge = Challenge()
        challenge.from_string(challenge_data)

        # Generate the NTLM Challenge Response
        yield self._challenge_response(challenge).get_data()

    def wrap_message(self, message):
        """
        Idiomatic Python implementation of initialize_security_context, implemented as a generator function using
        yield to both accept incoming and return outgoing authentication tokens
        :return: The response to be returned to the server
        """
        if not self.is_established:
            raise Exception("Context has not been established")
        if self._wrapper is None:
            raise Exception("Neither sealing or signing have been negotiated")
        else:
            return self._wrapper.seal(message)


    def unwrap(self):
        """

        :return: The wrapped message to be sent to the server
        """
        if not self.is_established:
            raise Exception("Context has not been established")
        if self._wrapper is None:
            raise Exception("Neither sealing or signing have been negotiated")
        else:
            return self._wrapper.seal(message)

    def _negotiate(self, flags):
        # returns the response
        return Negotiate(flags, self._authenticator.get_domain(), gethostname())

    def hack(self, flags, session):
        self._wrapper = Ntlm2Sealing(flags, session)

    def _challenge_response(self, challenge_token):
        flags = challenge_token['flags']

        # Compute the response material, this is rather complicated interplay between what client level we are
        # emulating and what the server is negotiating. It is made even more complex by when signing and sealing
        # are in use.

        # TODO: Check for the Target Info flag, if set we need to do the dance

        challenge = challenge_token['challenge']
        target_info = challenge_token['target_info_fields']

        ntlm_response, session_key, target_info = self._authenticator.get_ntlm_response(flags, challenge, target_info)
        lm_response = self._authenticator.get_lm_response(flags, challenge)

        # Ensure the negotiated flags guarantee at least the minimum level of session security required by the
        # client when the context was constructed
        if 'encrypt' in self._session_security and not flags & NegotiateFlag.NTLMSSP_SEAL:
            raise Exception("failed to negotiate session encryption")

        if 'sign' in self._session_security and not flags & NegotiateFlag.NTLMSSP_SIGN:
            raise Exception("failed to negotiate session encryption")

        # If session security was negotiated we should construct an appropriate object to perform the subsequent
        # message wrapping and unwrapping
        if flags & NegotiateFlag.NTLMSSP_SEAL:
            self._wrapper = Ntlm2Sealing(flags, self._authenticator.get_session_key())
        elif flags & NegotiateFlag.NTLMSSP_SIGN:
            self._wrapper = Ntlm2Signing(flags, session_key)

        if flags & NegotiateFlag.NTLMSSP_VERSION:
            flags &= 0xffffffff ^ NegotiateFlag.NTLMSSP_VERSION
        if flags & NegotiateFlag.NTLMSSP_NTLM_KEY:
           flags &= 0xffffffff ^ NegotiateFlag.NTLMSSP_NTLM_KEY

        self.is_established = True
        self.flags = flags

        return ChallengeResponse(flags, lm_response, ntlm_response,
                                 self._authenticator.get_domain(), self._authenticator.get_username(), session_key)
