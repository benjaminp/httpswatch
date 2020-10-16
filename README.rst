HTTPSWatch
==========

.. image:: https://travis-ci.org/benjaminp/httpswatch.svg?branch=master
    :target: https://travis-ci.org/benjaminp/httpswatch

This is the HTTPSWatch project, a retired website that tracks the HTTPS support of
prominent websites. This project is no longer under development.

The code is fairly simple. Python 3.4 is required. The ``check_https.py`` script
generates a small static site from JSON data in the ``config/`` directories and
Jinja2 templates from the ``templates/`` directory.

If you edit the HTML, please do not wrap HTML lines. (Paragraphs should be on
one line.)

Once ``check_https.py`` has been run, you can run ``testing_server.py`` to view
the website at ``localhost:8000``.
