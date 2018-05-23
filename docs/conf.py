# -*- coding: utf-8 -*-
import datetime as dt

from pgbedrock import __version__


project = 'pgbedrock'
copyright = 'Squarespace Data Engineering, {}'.format(dt.datetime.utcnow().year)
author = 'Squarespace Data Engineering'

version = __version__  # The short X.Y version
release = __version__  # The full version, including alpha/beta/rc tags

extensions = [
    'sphinx.ext.autosectionlabel',
]

exclude_patterns = ['_build', 'Thumbs.db', '.DS_Store']
html_theme = 'sphinx_rtd_theme'
master_doc = 'index'
source_suffix = '.rst'
