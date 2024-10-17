import pathlib
import sys
import unittest

ROOT_DIR = pathlib.Path(__file__).resolve().parent.parent

sys.path.append(str(ROOT_DIR))


class ViewTests(unittest.TestCase):

    def setUp(self) -> None:
        from wsgi import app
        app.testing = True
        self.app = app.test_client()
        return super().setUp()

    def test_home(self):
        response = self.app.get('/')
        self.assertEqual(response.status_code, 200)


if __name__ == '__main__':
    unittest.main()
