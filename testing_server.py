#/usr/bin/env python3

import argparse

from http import server as httpserver

class TestingRequestHandler(httpserver.SimpleHTTPRequestHandler):

    def translate_path(self, path):
        if not path.startswith("/static/"):
            if path == "/":
                path = "/global"
            path = "/out" + path + ".html"
        return super(TestingRequestHandler, self).translate_path(path)


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument('port', action='store',
                        default=8000, type=int,
                        nargs='?',
                        help='Specify alternate port [default: 8000]')
    args = parser.parse_args()
    handler_class = TestingRequestHandler
    httpserver.test(HandlerClass=handler_class, port=args.port)
