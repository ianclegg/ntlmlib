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
import re
import sys
import urllib
from setuptools import setup
from distutils.core import Command

__version__ = '0.0.1'
project_name = 'ntlmlib'

# PyPi supports only reStructuredText, so pandoc should be installed
# before uploading package
try:
    import pypandoc
    long_description = pypandoc.convert('README.md', 'rst')
except ImportError:
    long_description = ''

# We will run git to get the latest 'tag' and use this to release to PyPi
import subprocess
try:
    process = subprocess.Popen(['git', 'describe', '--abbrev=0'], stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    process.wait()
    git_tag = process.stdout.readline().strip()

    if process.returncode == 0:
        # versions must be in the range: 0.0.0 to 999.999.999
        version_match = re.match('(?:.*)[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}(?:.*)', git_tag)
        if version_match is None:
            __version__ = version_match.group()
        else:
            print "git tag '%s' is not a valid version number" % git_tag
    else:
        print "'git describe' failed to find the latest tag"

except OSError:
    print "Unable to run 'git describe --abbrev=0', ensure git is correctly installed"

print 'build package version: %s' % __version__
print 'build package name: %s' % project_name

class BootstrapEnvironmentCommand(Command):
    description = 'create project development environment from scratch'
    user_options = []

    def __init__(self, dist):
        Command.__init__(self, dist)
        self.project_dir = os.path.abspath(os.path.dirname(__file__))
        self.temp_dir = os.path.join(self.project_dir, '~temp')
        self.virtualenv_dir = os.path.join(self.project_dir, 'env')

    def initialize_options(self):
        pass

    def finalize_options(self):
        pass

    def run(self):
        self.setup_virtual_environment()

    def setup_virtual_environment(self):
        """Creates Python env if it not exists or re-create if outdated."""
        if not os.path.exists(self.temp_dir):
            os.makedirs(self.temp_dir)

        if not os.path.exists(self.virtualenv_dir):
            virtualenv_setup_path = os.path.join(self.temp_dir, 'virtualenv.py')
            urllib.urlretrieve(
                'https://raw.github.com/pypa/virtualenv/master/virtualenv.py',
                virtualenv_setup_path)
            virtualenv_prompt = '\({0}\)'.format(project_name) \
                if os.name == 'posix' else '({0})'.format(project_name)
            os.system('python {0} --prompt={1} env'.format(
                virtualenv_setup_path, virtualenv_prompt))
            self.activate_virtual_environment()
            easy_install_setup_path = os.path.join(self.temp_dir, 'ez_setup.py')
            urllib.urlretrieve(
                'http://peak.telecommunity.com/dist/ez_setup.py',
                easy_install_setup_path)
            os.system(
                'python {0} -U setuptools'.format(easy_install_setup_path))
            os.system(
                'pip install -r requirements.txt --download-cache={0}'.format(
                    self.temp_dir))

    def activate_virtual_environment(self):
        """ Activates virtual environment in the same way as activate.bat or activate.sh from virtualenv package """
        if not hasattr(sys, 'real_prefix') or 'VIRTUAL_ENV' not in os.environ:
            activate_this = '{0}/env/bin/activate_this.py'.format(
                self.project_dir)
            virtual_env_path = '{0}/env/bin:'.format(self.project_dir)
            if os.name != 'posix':
                activate_this = '{0}/env/Scripts/activate_this.py'.format(
                    self.project_dir)
                virtual_env_path = '{0}\env\Scripts;'.format(self.project_dir)

            execfile(activate_this, dict(__file__=activate_this))
            path = os.environ['PATH']
            os.environ['PATH'] = virtual_env_path + path


setup(
    name=project_name,
    version=__version__,
    description='A Python library for Windows NTLM authentication, signing and encryption',
    long_description=long_description,
    keywords='ntlm ntlmv2 gss gssapi sign seal authentication'.split(' '),
    author='Ian Clegg',
    author_email='ian.clegg@sourcewarp.com',
    url='http://github.com/iclegg/ntlmlib/',
    license='MIT license',
    packages=['ntlmlib'],
    package_data={},
    install_requires=['pycrypto'],
    cmdclass={'bootstrap_env': BootstrapEnvironmentCommand},
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