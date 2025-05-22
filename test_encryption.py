import os
import unittest
from app import app, db
from models import User

class EncryptionTestCase(unittest.TestCase):
    def setUp(self):
        # Set up test app and database
        app.config['TESTING'] = True
        app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///:memory:'
        self.app = app.test_client()
        with app.app_context():
            db.create_all()

    def tearDown(self):
        # Clean up database
        with app.app_context():
            db.session.remove()
            db.drop_all()

    def test_email_phone_encryption(self):
        with app.app_context():
            # Clean up existing test user if any
            existing_user = User.query.filter_by(username='testuser').first()
            if existing_user:
                db.session.delete(existing_user)
                db.session.commit()

            # Create a user with email and phone
            user = User(
                username='testuser',
                email='testuser@example.com',
                phone='1234567890',
                status='active'
            )
            user.set_password('testpassword')
            db.session.add(user)
            db.session.commit()

            # Fetch raw data from database
            raw_user = User.query.filter_by(username='testuser').first()
            self.assertIsNotNone(raw_user)

            # The stored _email and _phone should be encrypted and not equal to plaintext
            self.assertNotEqual(raw_user._email, 'testuser@example.com')
            self.assertNotEqual(raw_user._phone, '1234567890')

            # The decrypted properties should return original values
            self.assertEqual(raw_user.email, 'testuser@example.com')
            self.assertEqual(raw_user.phone, '1234567890')

if __name__ == '__main__':
    unittest.main()
