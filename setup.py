import ast
import re
from setuptools import setup


def ensure_one_level_of_quotes(text):
    # Converts '"foo"' to 'foo'
    return str(ast.literal_eval(text))


def get_version():
    """ Based on the functionality in pallets/click's setup.py
    (https://github.com/pallets/click/blob/master/setup.py) """
    _version_re = re.compile(r'__version__\s+=\s+(.*)')
    with open('pgbedrock/__init__.py', 'rb') as f:
        lines = f.read().decode('utf-8')
        version = ensure_one_level_of_quotes(_version_re.search(lines).group(1))
        return version


required = [
    'Cerberus',
    'click',
    'Jinja2',
    'psycopg2',
    'PyYAML',
]

setup(
    name='pgbedrock',
    description='Manage Postgres roles and privileges',
    long_description="Manage a Postgres cluster's roles, role memberships, role privileges, and schema ownership",
    version=get_version(),
    author='Squarespace Data Engineering',
    url='https://github.com/Squarespace/pgbedrock',
    download_url='https://github.com/Squarespace/pgbedrock/tarball/{}'.format(get_version()),
    packages=['pgbedrock'],
    license='Apache License 2.0',
    entry_points={
        'console_scripts': ['pgbedrock = pgbedrock.cli:entrypoint'],
    },
    install_requires=required,
    classifiers=[
        'Programming Language :: Python',
        'Programming Language :: Python :: 2',
        'Programming Language :: Python :: 3',
        'Programming Language :: Python :: 2.7',
        'Programming Language :: Python :: 3.6',
    ],
)
