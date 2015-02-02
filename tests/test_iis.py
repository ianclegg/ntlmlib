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

from ntlmlib.constants import NegotiateFlag
from ntlmlib.authentication import PasswordAuthentication
from ntlmlib.context import NtlmContext
from requests import Session
import binascii
import base64
import re


import win32security
import sspicon

auth = PasswordAuthentication('SERVER2012', 'Administrator', 'Pa55w0rd', compatibility=3, timestamp=True)
ntlm_context = NtlmContext(auth, session_security='none')
context = ntlm_context.initialize_security_context()

token = context.send(None)
# token.dump_flags()

encoded = base64.b64encode(token)
session = Session()
session.headers.update({'Authorization': 'NTLM ' + encoded})
response = session.post("http://192.168.137.154:5985/wsman")

ntlm_regex = re.compile('(?:.*,)*\s*NTLM\s*([^,]*),?', re.I)
authreq = response.headers.get('www-authenticate', None)
if authreq:
    match_obj = ntlm_regex.search(authreq)
    if match_obj and len(match_obj.group(1)) > 0:
        encoded = match_obj.group(1)

challenge = base64.b64decode(encoded)
# challenge.dump_flags()

print binascii.hexlify(challenge)
response_token = context.send(challenge)
# response_token.dump_flags()

encoded_response_token = base64.b64encode(response_token)
session.headers.update({'Authorization': 'NTLM ' + encoded_response_token})
response = session.get("http://192.168.137.154:5985/")
print response.content
