from os import environ, unlink
environ['LOG_LEVEL'] = 'TRACE'

import unittest
from os.path import dirname, isfile
from time import sleep
from tempfile import NamedTemporaryFile
from watchdog.observers import Observer

from .file import RulesFile
from .rule import PUBLIC, Rule

unittest.util._MAX_LENGTH=2000


class TestRulesFile(unittest.TestCase):
    def test_missing_file(self):
        with NamedTemporaryFile(delete=True) as f:
            file = RulesFile(dirname(f.name) + "/missing.txt")
            self.assertEqual([], file.rules())

    def test_existing_file(self):
        observer = Observer()
        tmpfile = NamedTemporaryFile(delete=False, mode='w+', encoding="utf-8")
        try:
            tmpfile.write("**:**:HEAD,GET:/public/**:<public>\nexample.com:**:GET:**:**:group")
            tmpfile.close()

            rules_file = RulesFile(tmpfile.name, observer)
            self.assertEqual(
                [
                    Rule(methods=["HEAD", "GET"], paths=["/public/**"], users=[PUBLIC]),
                    Rule(hosts=["example.com"], methods=["GET"], groups=["group"])
                ],
                rules_file.rules()
            )
        finally:
            observer.stop()
            unlink(tmpfile.name)

    def test_update(self):
        observer = Observer()
        tmpfile = NamedTemporaryFile(delete=False, mode='w+', encoding="utf-8")
        try:
            tmpfile.write("**:**:HEAD,GET:/public/**:<public>\n")
            tmpfile.close()

            rules_file = RulesFile(tmpfile.name, observer)
            self.assertEqual(
                [Rule(methods=["HEAD", "GET"], paths=["/public/**"], users=[PUBLIC])],
                rules_file.rules()
            )

            with open(tmpfile.name, 'a+', encoding='utf-8') as f:
                f.write("example.com:**:GET:**:**:group\n")

            sleep(1)

            self.assertEqual(
                [
                    Rule(methods=["HEAD", "GET"], paths=["/public/**"], users=[PUBLIC]),
                    Rule(hosts=["example.com"], methods=["GET"], groups=["group"]),
                ],
                rules_file.rules()
            )

        finally:
            observer.stop()
            unlink(tmpfile.name)

    def test_update_removed(self):
        observer = Observer()
        tmpfile = NamedTemporaryFile(delete=False, mode='w+', encoding="utf-8")
        try:
            tmpfile.write("**:**:HEAD,GET:/public/**:<public>\n")
            tmpfile.close()

            rules_file = RulesFile(tmpfile.name, observer)
            self.assertEqual(
                [Rule(methods=["HEAD", "GET"], paths=["/public/**"], users=[PUBLIC])],
                rules_file.rules()
            )

            unlink(tmpfile.name)

            sleep(1)

            self.assertEqual([], rules_file.rules())

        finally:
            observer.stop()
            if isfile(tmpfile.name):
                unlink(tmpfile.name)

    def test_update_created(self):
        observer = Observer()
        with NamedTemporaryFile(delete=False, mode='w+', encoding="utf-8") as f:
            file = dirname(f.name) + "/rules.conf"
            try:
                rules_file = RulesFile(file, observer)
                self.assertEqual([], rules_file.rules())

                with open(file, 'w+', encoding='utf-8') as r:
                    r.write("**:**:HEAD,GET:/public/**:<public>\n")

                sleep(1)

                self.assertEqual(
                    [Rule(methods=["HEAD", "GET"], paths=["/public/**"], users=[PUBLIC])],
                    rules_file.rules()
                )
            finally:
                observer.stop()
                if isfile(file):
                    unlink(file)


if __name__ == '__main__':
    unittest.main()        