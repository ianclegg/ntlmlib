# (c) 2015, Ian Clegg <ian.clegg@sourcewarp.com>
#
# ntlmlib is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# ntlmlib is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with 'ntlmlib'.  If not, see <http://www.gnu.org/licenses/>.
import os
import versioneer
from setuptools import setup

project_name = 'ntlmlib'

# versioneer configuration
versioneer.VCS = 'git'
versioneer.versionfile_source = os.path.join('ntlmlib', '_version.py')
versioneer.versionfile_build = os.path.join('ntlmlib', '_version.py')
versioneer.tag_prefix = ''
versioneer.parentdir_prefix = 'ntlmlib'

# PyPi supports only reStructuredText, so pandoc should be installed
# before uploading package
try:
    import pypandoc
    long_description = pypandoc.convert('README.md', 'rst')
except ImportError:
    long_description = ''

setup(
    name=project_name,
    version=versioneer.get_version(),
    description='A Python library for Windows NTLM authentication, signing and encryption',
    long_description=long_description,
    keywords='ntlm ntlmv2 gss gssapi sign seal authentication'.split(' '),
    author='Ian Clegg',
    author_email='ian.clegg@sourcewarp.com',
    url='http://github.com/ianclegg/ntlmlib/',
    license='MIT license',
    packages=['ntlmlib'],
    package_data={},
    install_requires=['pycrypto'],
    cmdclass=versioneer.get_cmdclass(),
    classifiers=[
        'Development Status :: 3 - Alpha',
        'Environment :: Console',
        'Intended Audience :: Developers',
        'Natural Language :: English',
        'License :: OSI Approved :: MIT License',
        'Programming Language :: Python',
        'Programming Language :: Python :: 2',
        'Programming Language :: Python :: 2.6',
        'Programming Language :: Python :: 2.7',
        'Programming Language :: Python :: 3',
        'Programming Language :: Python :: 3.2',
        'Programming Language :: Python :: 3.3',
        'Programming Language :: Python :: Implementation :: PyPy',
        'Topic :: Software Development :: Libraries :: Python Modules'
    ],
)
