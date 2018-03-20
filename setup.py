from setuptools import setup


def get_version():
    with open('package_version', 'r') as f:
        return f.readline().strip()


required = [
    'click==6.7',
    'psycopg2==2.7.3',
    'PyYAML==3.12',
    'Jinja2==2.9.6',
    'cerberus==1.1',
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
