from setuptools import setup, find_packages

from ptadapter import __version__
# Note: since ptadapter does not have any 3rd-party dependencies,
# it should be safe for setup.py to import it.

with open('README.md', 'rt') as readme_file:
    long_description = readme_file.read()

setup(
    name='ptadapter',
    version=__version__,
    description='Pluggable Transports Python interface & standalone tunnels',
    long_description=long_description,
    long_description_content_type='text/markdown',
    url='https://github.com/twisteroidambassador/pluggabletransportadapter',
    author='twisteroid ambassador',
    author_email='twisteroid.ambassador@gmail.com',
    license='GPLv3',
    classifiers=[
        'Development Status :: 4 - Beta',
        'Intended Audience :: Developers',
        'Framework :: AsyncIO',
        'License :: OSI Approved :: GNU General Public License v3 (GPLv3)',
        'Programming Language :: Python :: 3 :: Only',
        'Programming Language :: Python :: 3.7',
        'Programming Language :: Python :: 3.8',
        'Topic :: Internet :: Proxy Servers',
    ],
    keywords='pluggable-transport obfuscation tcp',
    project_urls={
        'Tracker': 'https://github.com/twisteroidambassador/pluggabletransportadapter/issues',
        'Documentation': 'https://twisteroidambassador.github.io/ptadapter-docs/',
    },
    packages=find_packages(),
    python_requires='>=3.7',
    entry_points={
        'console_scripts': [
            'ptadapter=ptadapter.console_script:main',
        ],
    },
    extras_require={
        'build-docs': ['sphinx_autodoc_typehints', 'sphinxcontrib-trio'],
    }
)
