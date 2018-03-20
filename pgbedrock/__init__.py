def _get_version():
    import os
    top_of_repo = os.path.abspath(os.path.dirname(os.path.dirname(__file__)))
    with open(os.path.join(top_of_repo, 'package_version'), 'r') as f:
        return f.readline().strip()


LOG_FORMAT = '%(levelname)s:%(filename)s:%(funcName)s:%(lineno)s - %(message)s'
__version__ = _get_version()
