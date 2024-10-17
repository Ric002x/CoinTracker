import pathlib
import sys
import unittest

ROOT_DIR = pathlib.Path(__file__).resolve().parent.parent

sys.path.append(str(ROOT_DIR))


class AuthTests(unittest.TestCase):

    def setUp(self) -> None:
        from wsgi import app

        app.testing = True
        self.app = app.test_client()

    def test_register_page(self):
        response = self.app.get('/register')
        self.assertEqual(response.status_code, 200)

    def test_login_page(self):
        response = self.app.get('/login')
        self.assertEqual(response.status_code, 200)


if __name__ == '__main__':
    unittest.main()
