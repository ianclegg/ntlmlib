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
from setuptools import setup

project_name = 'ntlmlib'

# PyPi supports only reStructuredText, so pandoc should be installed
# before uploading package
try:
    import pypandoc
    long_description = pypandoc.convert('README.md', 'rst')
except ImportError:
    long_description = ''

requires = [
    "cryptography",
    "ordereddict",
]

setup(
    name=project_name,
    version=0.72,
    description='A robust, fast and efficient ''first-class'' Python library for '
                'NTLMv1 and NTLMv2 authentication with signing and encryption',
    long_description=long_description,
    keywords='ntlm ntlmv2 gss gssapi sign seal authentication'.split(' '),
    author='Ian Clegg',
    author_email='ian.clegg@sourcewarp.com',
    url='http://github.com/ianclegg/ntlmlib/',
    license='Apache 2.0',
    packages=['ntlmlib'],
    package_data={},
    install_requires=requires,
    classifiers=[
        'Development Status :: 3 - Alpha',
        'Environment :: Console',
        'Intended Audience :: Developers',
        'Natural Language :: English',
        'License :: OSI Approved :: Apache Software License',
        'Programming Language :: Python',
        'Programming Language :: Python :: 2',
        'Programming Language :: Python :: 2.6',
        'Programming Language :: Python :: 2.7',
        'Programming Language :: Python :: 3',
        'Programming Language :: Python :: 3.2',
        'Programming Language :: Python :: 3.3',
        'Programming Language :: Python :: 3.4',
        'Programming Language :: Python :: 3.5',
        'Programming Language :: Python :: Implementation :: PyPy',
        'Topic :: Software Development :: Libraries :: Python Modules'
    ],
)
