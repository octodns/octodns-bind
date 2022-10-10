from os import environ
from setuptools import find_packages, setup
from subprocess import CalledProcessError, check_output


def descriptions():
    with open('README.md') as fh:
        ret = fh.read()
        first = ret.split('\n', 1)[0].replace('#', '')
        return first, ret


def version():
    version = 'unknown'
    with open('octodns_bind/__init__.py') as fh:
        for line in fh:
            if line.startswith('__VERSION__'):
                version = line.split("'")[1]
                break

    # pep440 style public & local version numbers
    if environ.get('OCTODNS_RELEASE', False):
        # public
        return version
    try:
        sha = check_output(['git', 'rev-parse', 'HEAD']).decode('utf-8')[:8]
    except (CalledProcessError, FileNotFoundError):
        sha = 'unknown'
    # local
    return f'{version}+{sha}'


description, long_description = descriptions()

tests_require = ('pytest', 'pytest-cov', 'pytest-network')

setup(
    author='Adam Smith',
    author_email='zero1three@gmail.com',
    description=description,
    extras_require={
        'dev': tests_require
        + (
            'black>=22.3.0',
            'build>=0.7.0',
            'pyflakes>=2.2.0',
            'readme_renderer[md]>=26.0',
            'twine>=3.4.2',
        )
    },
    install_requires=('dnspython>=2.2.1', 'octodns>=0.9.20'),
    license='MIT',
    long_description=long_description,
    long_description_content_type='text/markdown',
    name='octodns-bind',
    packages=find_packages(),
    python_requires='>=3.6',
    tests_require=tests_require,
    url='https://github.com/octodns/octodns-bind',
    version=version(),
)
