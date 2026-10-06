"""Run after the README's local database initialization: python -m unittest testing.test_auth_flow."""
import unittest
from main import app
from model.user import User


class AuthenticationFlowTests(unittest.TestCase):
    def setUp(self):
        self.client = app.test_client()
        self.credentials = {
            'uid': app.config['USER_UID'],
            'password': app.config['USER_PASSWORD'],
        }

    def login(self):
        response = self.client.post('/api/authenticate', json=self.credentials)
        self.assertEqual(response.status_code, 200)

    def test_cookie_identity_and_logout(self):
        self.login()
        identity = self.client.get('/api/id')
        self.assertEqual(identity.status_code, 200)
        self.assertEqual(identity.json['uid'], self.credentials['uid'])
        self.assertNotIn('password', identity.json)
        self.assertEqual(self.client.get('/api/id').status_code, 200)
        self.assertEqual(self.client.delete('/api/authenticate').status_code, 200)
        self.assertEqual(self.client.get('/api/id').status_code, 401)

    def test_logout_clears_flask_login_session_too(self):
        with app.app_context():
            user = User.query.filter_by(_uid=self.credentials['uid']).one()
            session_id = user.get_id()
        with self.client.session_transaction() as session:
            session['_user_id'] = session_id
            session['_fresh'] = True
        self.assertEqual(self.client.get('/api/id').status_code, 200)
        self.assertEqual(self.client.delete('/api/authenticate').status_code, 200)
        self.assertEqual(self.client.get('/api/id').status_code, 401)

    def test_invalid_login_does_not_authenticate(self):
        response = self.client.post('/api/authenticate', json={
            'uid': self.credentials['uid'], 'password': 'invalid-integration-password',
        })
        self.assertEqual(response.status_code, 401)
        self.assertEqual(self.client.get('/api/id').status_code, 401)

    def test_credentialed_cors_preflight(self):
        for hostname in ('localhost', '127.0.0.1'):
            origin = f'http://{hostname}:4599'
            response = self.client.options('/api/authenticate', headers={
                'Origin': origin,
                'Access-Control-Request-Method': 'POST',
                'Access-Control-Request-Headers': 'content-type,x-origin',
            })
            self.assertEqual(response.status_code, 200)
            self.assertEqual(response.headers['Access-Control-Allow-Origin'], origin)
            self.assertEqual(response.headers['Access-Control-Allow-Credentials'], 'true')
