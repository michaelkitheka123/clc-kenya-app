
import kivy
import time
from kivy.app import App
from kivy.uix.image import Image
from kivy.uix.screenmanager import ScreenManager, Screen
from kivy.uix.textinput import TextInput
from kivy.uix.spinner import Spinner, SpinnerOption
from kivy.uix.label import Label
from kivy.uix.button import Button
from kivy.uix.boxlayout import BoxLayout
from kivy.uix.floatlayout import FloatLayout
from kivy.uix.scrollview import ScrollView
from kivy.properties import BooleanProperty, StringProperty, NumericProperty
from kivy.clock import Clock
from kivy.core.window import Window
from kivy.graphics import Color, RoundedRectangle, Line, Rectangle 
from kivy.animation import Animation
from kivy.metrics import dp
from kivy.metrics import sp
from kivy.uix.widget import Widget
import re
import sqlite3
from datetime import datetime, timedelta
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
import hashlib
import secrets
import json
import math
from kivy.core.text import LabelBase
from kivy.app import App
import os
from kivy.properties import StringProperty, ListProperty
from kivy.uix.boxlayout import BoxLayout
import asyncio  # ADD THIS IMPORT
from kivy.uix.behaviors import ButtonBehavior

# Add these custom widget classes before your AboutScreen class

import os
from kivy.core.text import LabelBase

# Get the absolute path to the current folder (where this file is)
current_dir = os.path.dirname(os.path.abspath(__file__))

# Path to your fonts folder
fonts_dir = os.path.join(current_dir, 'fonts', 'otfs')

# Register Font Awesome fonts with readable names
LabelBase.register(
    name='FontAwesomeSolid',
    fn_regular=os.path.join(fonts_dir, 'Font Awesome 7 Free-Solid-900.otf')
)

LabelBase.register(
    name='FontAwesomeRegular',
    fn_regular=os.path.join(fonts_dir, 'Font Awesome 7 Free-Regular-400.otf')
)

LabelBase.register(
    name='FontAwesomeBrands',
    fn_regular=os.path.join(fonts_dir, 'Font Awesome 7 Brands-Regular-400.otf')
)

print("Font Awesome fonts registered successfully!")


# Import the KV file
from kivy.lang import Builder
Builder.load_file('ui.kv')

# OTP Configuration
class OTPConfig:
    OTP_LENGTH = 6
    OTP_EXPIRY_MINUTES = 10
    OTP_RESEND_COOLDOWN = 60
    
    SMTP_SERVER = "smtp.gmail.com"
    SMTP_PORT = 587
    EMAIL_SENDER = "michael.mutemi16@gmail.com"
    EMAIL_PASSWORD = "pcbylmtgeaetcoto"
    
    MAX_ATTEMPTS_PER_OTP = 3
    MAX_OTP_REQUESTS_PER_HOUR = 5

# OTP Utility Class
class OTPUtils:
    @staticmethod
    def generate_otp():
        return ''.join([str(secrets.randbelow(10)) for _ in range(OTPConfig.OTP_LENGTH)])
    
    @staticmethod
    def hash_otp(otp_code):
        return hashlib.sha256(otp_code.encode()).hexdigest()
    
    @staticmethod
    def send_otp_email(recipient_email, otp_code, is_password_reset=False):
        try:
            print(f"Attempting to send OTP to: {recipient_email}")
            
            if not recipient_email or recipient_email.strip() == "":
                print("❌ ERROR: Recipient email is empty!")
                return False
            
            if is_password_reset:
                subject = "Password Reset OTP - CLC Kenya"
                body = f"""
                <html>
                <body>
                    <h2>CLC Kenya - Password Reset</h2>
                    <p>Your password reset OTP code is: <strong style="font-size: 24px; color: #2E86AB;">{otp_code}</strong></p>
                    <p>This code will expire in {OTPConfig.OTP_EXPIRY_MINUTES} minutes.</p>
                    <p>If you didn't request a password reset, please ignore this email.</p>
                    <br>
                    <p>Best regards,<br>Christian Life Community Kenya</p>
                </body>
                </html>
                """
            else:
                subject = "Your OTP Verification Code - CLC Kenya"
                body = f"""
                <html>
                <body>
                    <h2>CLC Kenya - Account Verification</h2>
                    <p>Your OTP verification code is: <strong style="font-size: 24px; color: #2E86AB;">{otp_code}</strong></p>
                    <p>This code will expire in {OTPConfig.OTP_EXPIRY_MINUTES} minutes.</p>
                    <p>If you didn't request this code, please ignore this email.</p>
                    <br>
                    <p>Best regards,<br>Christian Life Community Kenya</p>
                </body>
                </html>
                """
            
            msg = MIMEMultipart()
            msg['From'] = OTPConfig.EMAIL_SENDER
            msg['To'] = recipient_email
            msg['Subject'] = subject
            msg.attach(MIMEText(body, 'html'))
            
            server = smtplib.SMTP(OTPConfig.SMTP_SERVER, OTPConfig.SMTP_PORT, timeout=30)
            server.set_debuglevel(1)
            server.starttls()
            
            password_clean = OTPConfig.EMAIL_PASSWORD.replace(" ", "")
            server.login(OTPConfig.EMAIL_SENDER, password_clean)
            
            text = msg.as_string()
            server.sendmail(OTPConfig.EMAIL_SENDER, recipient_email, text)
            server.quit()
            
            print(f"✅ OTP email sent successfully to {recipient_email}")
            return True
            
        except smtplib.SMTPAuthenticationError as e:
            print(f"❌ SMTP Authentication Error: {e}")
            return False
        except Exception as e:
            print(f"❌ Unexpected error sending email: {e}")
            return False

def test_email_configuration():
    try:
        print("🔧 Testing email configuration...")
        server = smtplib.SMTP(OTPConfig.SMTP_SERVER, OTPConfig.SMTP_PORT, timeout=30)
        server.set_debuglevel(1)
        server.starttls()
        
        password_clean = OTPConfig.EMAIL_PASSWORD.replace(" ", "")
        server.login(OTPConfig.EMAIL_SENDER, password_clean)
        server.quit()
        
        print("✅ Email configuration test PASSED")
        return True
    except Exception as e:
        print(f"❌ Email configuration test FAILED: {e}")
        return False

# Custom Widget Classes
class ModernInputField(TextInput):
    pass

class ModernSpinner(Spinner):
    pass

class DateSpinner(Spinner):
    pass

class ModernSpinnerOption(SpinnerOption):
    pass

class ErrorLabel(Label):
    pass

class OTPInputField(TextInput):
    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        self.background_color = (0.975, 0.975, 0.975, 0.9)
        self.background_normal = ''
        self.background_active = ''
        self.foreground_color = (0.11, 0.168, 0.227, 1)
        self.cursor_color = (0.11, 0.168, 0.227, 1)
        
        from kivy.metrics import dp
        with self.canvas.before:
            Color(0.949, 0.788, 0.298, 0.3)
            self.rect = RoundedRectangle(
                size=self.size,
                pos=self.pos,
                radius=[dp(8),]
            )
        
        self.bind(pos=self._update_rect, size=self._update_rect)
    
    def _update_rect(self, instance, value):
        self.rect.pos = instance.pos
        self.rect.size = instance.size
    
    def insert_text(self, substring, from_undo=False):
        if substring.isdigit() and len(self.text) == 0:
            return super().insert_text(substring, from_undo=from_undo)
        return super().insert_text('', from_undo=from_undo)

# Animated Widgets for About Screen
class AnimatedLabel(Label):
    """Custom label that stores original position for animations"""
    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        self.original_pos = (0, 0)
        self.original_font_size = self.font_size
    
    def on_pos(self, instance, value):
        self.original_pos = value

class AnimatedImage(Image):
    """Custom image that stores original position for animations"""
    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        self.original_pos = (0, 0)
    
    def on_pos(self, instance, value):
        self.original_pos = value

class ValidationUtils:
    @staticmethod
    def validate_email(email):
        if not email:
            return False
        pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
        return bool(re.match(pattern, email))
    
    @staticmethod
    def validate_kenyan_phone(phone):
        if not phone:
            return False
        pattern = r'^(\+?254|0)[\s\-]?[17]\d{1,2}[\s\-]?\d{3}[\s\-]?\d{3,4}$'
        return bool(re.match(pattern, phone))
    
    @staticmethod
    def validate_password_strength(password):
        if not password:
            return False, "Password is required"
        if len(password) < 8:
            return False, "Password must be at least 8 characters"
        if not re.search(r'[A-Z]', password):
            return False, "Password must contain uppercase letters"
        if not re.search(r'[a-z]', password):
            return False, "Password must contain lowercase letters"
        if not re.search(r'\d', password):
            return False, "Password must contain numbers"
        if not re.search(r'[!@#$%^&*(),.?":{}|<>]', password):
            return False, "Password must contain special characters"
        return True, "Password is strong"

class KenyanInstitutions:
    @staticmethod
    def get_tertiary_institutions():
        return sorted([
            "University of Nairobi", "Kenyatta University", "Moi University",
            "Jomo Kenyatta University of Agriculture and Technology", "Egerton University",
            "Maseno University", "Technical University of Kenya", "Technical University of Mombasa",
            "Dedan Kimathi University of Technology", "Masinde Muliro University of Science and Technology",
            "Murang'a University of Technology", "Meru University of Science and Technology",
            "Kibabii University", "Karatina University", "Laikipia University",
            "University of Eldoret", "Pwani University", "Kisii University",
            "Rongo University", "South Eastern Kenya University", "Maasai Mara University",
            "Cooperative University of Kenya", "Kenya Methodist University", "Mount Kenya University",
            "Strathmore University", "United States International University Africa",
            "Catholic University of Eastern Africa", "Daystar University", "Africa Nazarene University",
            "Scott Christian University", "St. Paul's University", "Kabarak University",
            "KCA University", "Riara University", "Zetech University"
        ])

# ADD REGION MAPPING & AUTO-ASSIGNMENT LOGIC AFTER KenyanInstitutions class
REGION_MAPPING = {
    'nairobi': {
        'institutions': ['Kenyatta University', 'University of Nairobi', 'Tangaza University College', 'Consolata Shrine Parish', 'St. Paul\'s University Chapel'],
        'counties': ['Nairobi', 'Kiambu', 'Machakos']
    },
    'rift_valley': {
        'institutions': ['Moi University', 'Catholic Chaplaincy Eldoret', 'Egerton University'],
        'counties': ['Uasin Gishu', 'Nakuru', 'Elgeyo Marakwet']
    },
    'western': {
        'institutions': ['Masinde Muliro University', 'Catholic Diocese of Kakamega'],
        'counties': ['Kakamega', 'Bungoma', 'Vihiga']
    },
    'coastal': {
        'institutions': ['Technical University of Mombasa', 'Catholic Chaplaincy Mombasa'],
        'counties': ['Mombasa', 'Kilifi', 'Kwale']
    },
    'central': {
        'institutions': ['Dedan Kimathi University', 'Catholic Diocese of Nyeri'],
        'counties': ['Nyeri', 'Murang\'a', 'Kirinyaga']
    }
}

def auto_assign_region(occupation, institution=None, residence=None):
    """Auto-assign region based on institution or residence"""
    if occupation == 'Student' and institution:
        for region, data in REGION_MAPPING.items():
            if institution in data['institutions']:
                return region
    elif occupation == 'Alumni' and residence:
        for region, data in REGION_MAPPING.items():
            if residence in data['counties']:
                return region
    return 'nairobi'  # Default fallback

class DatabaseManager:
    def __init__(self, db_name='users.db'):
        self.db_name = db_name
        self.init_database()
    
    def init_database(self):
        conn = sqlite3.connect(self.db_name)
        cursor = conn.cursor()
        
        # Create tables with latest schema
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                name TEXT NOT NULL,
                email TEXT UNIQUE NOT NULL,
                phone TEXT NOT NULL,
                date_of_birth TEXT NOT NULL,
                occupation TEXT NOT NULL,
                institution TEXT,
                residence TEXT,
                password_hash TEXT NOT NULL,
                is_verified BOOLEAN DEFAULT FALSE,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                region TEXT,
                is_admin BOOLEAN DEFAULT FALSE
            )
        ''')
        
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS otp_verification (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                email TEXT NOT NULL,
                otp_hash TEXT NOT NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                expires_at TIMESTAMP NOT NULL,
                attempts INTEGER DEFAULT 0,
                is_used BOOLEAN DEFAULT FALSE,
                user_data TEXT,
                purpose TEXT DEFAULT 'registration'
            )
        ''')
        
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS otp_rate_limit (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                email TEXT NOT NULL,
                request_count INTEGER DEFAULT 1,
                hour_window TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        ''')
        
        # Check and add missing columns for users table
        cursor.execute("PRAGMA table_info(users)")
        users_columns = [column[1] for column in cursor.fetchall()]
        
        missing_users_columns = []
        if 'region' not in users_columns:
            missing_users_columns.append('region')
            cursor.execute('ALTER TABLE users ADD COLUMN region TEXT')
        
        if 'is_admin' not in users_columns:
            missing_users_columns.append('is_admin')
            cursor.execute('ALTER TABLE users ADD COLUMN is_admin BOOLEAN DEFAULT FALSE')
        
        if missing_users_columns:
            print(f"✅ Added missing columns to users table: {', '.join(missing_users_columns)}")
        
        # Check and add missing columns for otp_verification table
        cursor.execute("PRAGMA table_info(otp_verification)")
        otp_columns = [column[1] for column in cursor.fetchall()]
        
        missing_otp_columns = []
        if 'purpose' not in otp_columns:
            missing_otp_columns.append('purpose')
            cursor.execute('ALTER TABLE otp_verification ADD COLUMN purpose TEXT DEFAULT "registration"')
        
        if 'user_data' not in otp_columns:
            missing_otp_columns.append('user_data')
            cursor.execute('ALTER TABLE otp_verification ADD COLUMN user_data TEXT')
        
        if missing_otp_columns:
            print(f"✅ Added missing columns to otp_verification table: {', '.join(missing_otp_columns)}")
        
        # Set first user as admin for testing (you can remove this later)
        cursor.execute('SELECT COUNT(*) FROM users')
        user_count = cursor.fetchone()[0]
        if user_count == 0:
            print("ℹ️  First registered user will be set as admin")
        
        conn.commit()
        conn.close()
        print("✅ Database initialization completed successfully")
    
    def save_user(self, user_data):
        try:
            conn = sqlite3.connect(self.db_name)
            cursor = conn.cursor()
            
            # Check if this is the first user (set as admin)
            cursor.execute('SELECT COUNT(*) FROM users')
            user_count = cursor.fetchone()[0]
            is_admin = user_count == 0  # First user becomes admin
            
            # Get region from user_data or assign default
            region = user_data.get('region', 'nairobi')
            
            cursor.execute('''
                INSERT INTO users (name, email, phone, date_of_birth, occupation, institution, residence, password_hash, is_verified, region, is_admin)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ''', (
                user_data['name'], user_data['email'], user_data['phone'],
                user_data['date_of_birth'], user_data['occupation'],
                user_data.get('institution'), user_data.get('residence'),
                user_data['password_hash'], True, region, is_admin
            ))
            user_id = cursor.lastrowid
            
            if is_admin:
                print(f"👑 First user set as admin: {user_data['email']}")
            
            conn.commit()
            conn.close()
            return True, user_id
        except sqlite3.IntegrityError:
            return False, "Email already exists"
        except Exception as e:
            return False, f"Database error: {str(e)}"
    
    def store_otp(self, email, otp_hash, user_data=None, purpose='registration'):
        try:
            expires_at = datetime.now() + timedelta(minutes=OTPConfig.OTP_EXPIRY_MINUTES)
            
            conn = sqlite3.connect(self.db_name)
            cursor = conn.cursor()
            
            cursor.execute('''
                UPDATE otp_verification 
                SET is_used = TRUE 
                WHERE email = ? AND is_used = FALSE
            ''', (email,))
            
            user_data_json = json.dumps(user_data) if user_data else None
            
            cursor.execute('''
                INSERT INTO otp_verification (email, otp_hash, expires_at, user_data, purpose)
                VALUES (?, ?, ?, ?, ?)
            ''', (email, otp_hash, expires_at, user_data_json, purpose))
            
            conn.commit()
            conn.close()
            return True
        except Exception as e:
            print(f"Error storing OTP: {e}")
            return False
    
    def verify_otp(self, email, otp_code):
        try:
            conn = sqlite3.connect(self.db_name)
            cursor = conn.cursor()
            
            cursor.execute('''
                SELECT id, otp_hash, expires_at, attempts, user_data, purpose
                FROM otp_verification 
                WHERE email = ? AND is_used = FALSE 
                ORDER BY created_at DESC 
                LIMIT 1
            ''', (email,))
            
            result = cursor.fetchone()
            
            if not result:
                return False, "No OTP found for this email", None, None
            
            otp_id, stored_hash, expires_at, attempts, user_data_json, purpose = result
            
            if datetime.now() > datetime.fromisoformat(expires_at):
                return False, "OTP has expired", None, purpose
            
            if attempts >= OTPConfig.MAX_ATTEMPTS_PER_OTP:
                return False, "Too many attempts. Please request a new OTP", None, purpose
            
            input_hash = hashlib.sha256(otp_code.encode()).hexdigest()
            if input_hash != stored_hash:
                cursor.execute('''
                    UPDATE otp_verification 
                    SET attempts = attempts + 1 
                    WHERE id = ?
                ''', (otp_id,))
                conn.commit()
                remaining_attempts = OTPConfig.MAX_ATTEMPTS_PER_OTP - (attempts + 1)
                return False, f"Invalid OTP. {remaining_attempts} attempts remaining", None, purpose
            
            cursor.execute('''
                UPDATE otp_verification 
                SET is_used = TRUE 
                WHERE id = ?
            ''', (otp_id,))
            
            conn.commit()
            conn.close()
            
            user_data = json.loads(user_data_json) if user_data_json else None
            return True, "OTP verified successfully", user_data, purpose
            
        except Exception as e:
            return False, f"Verification error: {str(e)}", None, None
    
    def check_rate_limit(self, email):
        try:
            conn = sqlite3.connect(self.db_name)
            cursor = conn.cursor()
            
            hour_ago = datetime.now() - timedelta(hours=1)
            cursor.execute('''
                DELETE FROM otp_rate_limit 
                WHERE hour_window < ?
            ''', (hour_ago,))
            
            cursor.execute('''
                SELECT request_count 
                FROM otp_rate_limit 
                WHERE email = ? AND hour_window >= ?
            ''', (email, hour_ago))
            
            result = cursor.fetchone()
            
            if result:
                request_count = result[0]
                if request_count >= OTPConfig.MAX_OTP_REQUESTS_PER_HOUR:
                    conn.close()
                    return False, f"Too many OTP requests. Please wait before requesting another."
                
                cursor.execute('''
                    UPDATE otp_rate_limit 
                    SET request_count = request_count + 1 
                    WHERE email = ?
                ''', (email,))
            else:
                cursor.execute('''
                    INSERT INTO otp_rate_limit (email, request_count, hour_window)
                    VALUES (?, 1, ?)
                ''', (email, datetime.now()))
            
            conn.commit()
            conn.close()
            return True, "Rate limit check passed"
            
        except Exception as e:
            return False, f"Rate limit error: {str(e)}"
    
    def verify_user_credentials(self, email, password):
        try:
            conn = sqlite3.connect(self.db_name)
            cursor = conn.cursor()
            
            cursor.execute('''
                SELECT name, password_hash, region, is_admin FROM users WHERE email = ?
            ''', (email,))
            
            result = cursor.fetchone()
            conn.close()
            
            if not result:
                return False, "User not found", None, None, None
            
            user_name, stored_hash, region, is_admin = result
            if password == stored_hash:
                return True, "Login successful", user_name, region, is_admin
            else:
                return False, "Invalid password", None, None, None
                
        except Exception as e:
            return False, f"Login error: {str(e)}", None, None, None
    
    def update_user_password(self, email, new_password):
        try:
            conn = sqlite3.connect(self.db_name)
            cursor = conn.cursor()
            
            cursor.execute('''
                UPDATE users SET password_hash = ? WHERE email = ?
            ''', (new_password, email))
            
            conn.commit()
            conn.close()
            return True, "Password updated successfully"
        except Exception as e:
            return False, f"Password update error: {str(e)}"
    
    def check_email_exists(self, email):
        try:
            conn = sqlite3.connect(self.db_name)
            cursor = conn.cursor()
            
            cursor.execute('''
                SELECT id FROM users WHERE email = ?
            ''', (email,))
            
            result = cursor.fetchone()
            conn.close()
            
            return result is not None
        except Exception as e:
            print(f"Error checking email: {e}")
            return False
    
    # NEW METHODS FOR ADMIN SETTINGS FUNCTIONALITY
    def get_current_user(self):
        """Get current logged-in user data"""
        try:
            app = App.get_running_app()
            current_email = getattr(app, 'current_user_email', None)
            if not current_email:
                print("⚠️ No current user email found")
                return None
            
            return self.get_user_by_email(current_email)
        except Exception as e:
            print(f"Error getting current user: {e}")
            return None

    def logout_current_user(self):
        """Clear current user session"""
        try:
            app = App.get_running_app()
            # Clear all user session data
            if hasattr(app, 'current_user'):
                delattr(app, 'current_user')
            if hasattr(app, 'current_user_email'):
                delattr(app, 'current_user_email')
            if hasattr(app, 'is_admin'):
                delattr(app, 'is_admin')
            print("✅ User session cleared")
            return True
        except Exception as e:
            print(f"Error during logout: {e}")
            return False

    def get_user_by_email(self, email):
        """Get complete user data by email"""
        try:
            conn = sqlite3.connect(self.db_name)
            cursor = conn.cursor()
            
            cursor.execute('''
                SELECT id, name, email, phone, occupation, institution, residence, region, is_admin 
                FROM users WHERE email = ?
            ''', (email,))
            
            result = cursor.fetchone()
            conn.close()
            
            if result:
                user_id, name, email, phone, occupation, institution, residence, region, is_admin = result
                return {
                    'id': user_id,
                    'name': name,
                    'email': email,
                    'phone': phone,
                    'occupation': occupation,
                    'institution': institution,
                    'residence': residence,
                    'region': region,
                    'is_admin': bool(is_admin)
                }
            return None
        except Exception as e:
            print(f"Error getting user: {e}")
            return None
    
    def update_user_region(self, user_id, region):
        """Update user's region"""
        try:
            conn = sqlite3.connect(self.db_name)
            cursor = conn.cursor()
            
            cursor.execute('''
                UPDATE users SET region = ? WHERE id = ?
            ''', (region, user_id))
            
            conn.commit()
            conn.close()
            return True
        except Exception as e:
            print(f"Error updating region: {e}")
            return False
    
    def promote_to_admin(self, user_id):
        """Promote a user to admin"""
        try:
            conn = sqlite3.connect(self.db_name)
            cursor = conn.cursor()
            
            cursor.execute('''
                UPDATE users SET is_admin = TRUE WHERE id = ?
            ''', (user_id,))
            
            conn.commit()
            conn.close()
            print(f"✅ User {user_id} promoted to admin")
            return True
        except Exception as e:
            print(f"Error promoting to admin: {e}")
            return False
    
    def demote_from_admin(self, user_id):
        """Demote a user from admin"""
        try:
            conn = sqlite3.connect(self.db_name)
            cursor = conn.cursor()
            
            cursor.execute('''
                UPDATE users SET is_admin = FALSE WHERE id = ?
            ''', (user_id,))
            
            conn.commit()
            conn.close()
            print(f"✅ User {user_id} demoted from admin")
            return True
        except Exception as e:
            print(f"Error demoting from admin: {e}")
            return False
    
    def get_all_users(self):
        """Get all users (for admin purposes)"""
        try:
            conn = sqlite3.connect(self.db_name)
            cursor = conn.cursor()
            
            cursor.execute('''
                SELECT id, name, email, region, is_admin FROM users ORDER BY name
            ''')
            
            users = []
            for row in cursor.fetchall():
                user_id, name, email, region, is_admin = row
                users.append({
                    'id': user_id,
                    'name': name,
                    'email': email,
                    'region': region,
                    'is_admin': bool(is_admin)
                })
            
            conn.close()
            return users
        except Exception as e:
            print(f"Error getting all users: {e}")
            return []
# NEW: User Dashboard Screen
class UserDashboardScreen(Screen):
    first_name = StringProperty("User")
    is_admin = BooleanProperty(False)

    def on_pre_enter(self):
        self.load_user_data()
        print(f"Dashboard loaded for {self.first_name} (Admin: {self.is_admin})")

    def load_user_data(self):
        from kivy.app import App
        app = App.get_running_app()

        user_data = getattr(app, 'current_user', None)
        if not user_data:
            print("⚠️ No current user loaded")
            return

        # Set first name and admin status
        self.first_name = user_data.get('name', 'User').split()[0]
        self.is_admin = user_data.get('is_admin', False)
        print(f"Dashboard loaded for {self.first_name} (Admin: {self.is_admin})")


    # Navigation methods
    def navigate_to_about(self):
        self._navigate('about', "About")

    def navigate_to_chats(self):
        target = 'admin_chat' if self.is_admin else 'user_chat'
        self._navigate(target, "Chat")

    def navigate_to_notifications(self):
        # Placeholder until notifications screens are added
        print(f"Navigate to {'Admin' if self.is_admin else 'User'} Notifications")

    def navigate_to_settings(self):
        target = 'AdminSettingsScreen' if self.is_admin else 'UserSettingsScreen'
        self._navigate(target, "Settings")

    def _navigate(self, screen_name, screen_label):
        try:
            self.manager.current = screen_name
            print(f"Navigated to {screen_label} screen ({'Admin' if self.is_admin else 'User'})")
        except Exception as e:
            print(f"{screen_label} navigation error: {e}")

# About Screen with Animations
class AboutScreen(Screen):
    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        self.animations_played = False
        
    def on_enter(self):
        if not self.animations_played:
            Clock.schedule_once(self.animate_content, 0.1)
            
    def animate_content(self, dt):
        try:
            # Get all main sections to animate
            section_ids = [
                'hero_section', 'mission_section', 'vision_section',
                'who_we_are_section', 'what_we_do_section', 'values_section',
                'history_section', 'symbolism_section'
            ]
            
            sections = []
            for section_id in section_ids:
                if hasattr(self.ids, section_id):
                    widget = getattr(self.ids, section_id)
                    if widget:
                        sections.append(widget)
            
            # Animate sections sequentially
            for i, section in enumerate(sections):
                if section:
                    section.opacity = 0
                    section.y -= dp(30)
                    
                    anim = Animation(
                        opacity=1,
                        y=section.y + dp(30),
                        duration=0.6,
                        transition='out_back'
                    )
                    anim.start(section)
            
            self.animations_played = True
            print("About screen animations completed")
            
        except Exception as e:
            print(f"Animation error: {e}")
    
    def go_back(self):
        try:
            # Try to go back to dashboard, fallback to login
            if 'user_dashboard' in self.manager.screen_names:
                self.manager.current = 'user_dashboard'
            else:
                self.manager.current = 'login'
            print("Navigated back from About screen")
        except Exception as e:
            print(f"Back navigation error: {e}")
            self.manager.current = 'login'

# ADD CHAT SCREEN CLASS BEFORE ScreenManagement
from kivy.properties import DictProperty

class ChatRouterScreen(Screen):
    """
    Decides which chat screen to render (AdminChatScreen or UserChatScreen)
    depending on the logged-in user's role.
    """

    def on_pre_enter(self):
        try:
            app = App.get_running_app()
            db = getattr(app, "db_manager", None)

            # Fetch logged-in user info (from session or DB)
            current_email = getattr(app, "user_email", None)
            user_data = None

            if current_email and db:
                # ✅ get_user_by_email returns dict with is_admin
                user_data = db.get_user_by_email(current_email)

            if not user_data:
                # fallback for dev/test
                print("⚠️ No logged-in user found — using fallback demo user")
                user_data = {
                    "id": "guest",
                    "email": "demo@clc.org",
                    "is_admin": False,
                    "region": "nairobi"
                }

            # Determine if admin
            is_admin = bool(user_data.get("is_admin", False))

            # Cache current user info in App for later use
            app.current_user = user_data
            app.user_email = user_data["email"]
            app.user_region = user_data.get("region", "nairobi")

            # ✅ Route user
            if is_admin:
                print(f"🧑‍💼 Admin detected ({user_data['email']}) — opening AdminChatScreen")
                self.manager.transition.direction = "left"
                self.manager.current = "admin_chat"
            else:
                print(f"🙋 Regular user ({user_data['email']}) — opening UserChatScreen")
                self.manager.transition.direction = "left"
                self.manager.current = "user_chat"

        except Exception as e:
            print(f"❌ ChatRouterScreen error: {e}")

# ============================================
# 🧑‍💼 AdminChatScreen — Full Production Version
# ============================================
import os
import time
import json
import threading
import asyncio
from datetime import datetime
from kivy.app import App
from kivy.clock import Clock
from kivy.metrics import dp, sp
from kivy.uix.screenmanager import Screen
from kivy.uix.boxlayout import BoxLayout
from kivy.uix.label import Label
from kivy.uix.image import AsyncImage
from kivy.uix.popup import Popup
from kivy.uix.filechooser import FileChooserListView
from kivy.uix.scrollview import ScrollView
from kivy.uix.modalview import ModalView
from kivy.uix.button import Button
from kivy.lang import Builder
from kivy.uix.button import Button
from kivy.clock import Clock

class LongPressButton(Button):
    """A button that detects long press (0.45s by default)"""
    __events__ = ('on_long_press',)

    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        self._lp_ev = None

    def on_touch_down(self, touch):
        if self.collide_point(*touch.pos):
            # Schedule a long-press trigger
            self._lp_ev = Clock.schedule_once(lambda dt: self.dispatch('on_long_press'), 0.45)
        return super().on_touch_down(touch)

    def on_touch_up(self, touch):
        # Cancel long-press if touch is released too soon
        if self._lp_ev:
            Clock.unschedule(self._lp_ev)
            self._lp_ev = None
        return super().on_touch_up(touch)

    def on_long_press(self, *args):
        """Triggered automatically after hold duration."""
        pass
from kivy.factory import Factory
Factory.register('LongPressButton', cls=LongPressButton)
from kivy.uix.screenmanager import Screen
from kivy.app import App
from kivy.clock import Clock
from kivy.lang import Builder
from kivy.factory import Factory
from kivy.metrics import dp, sp
from kivy.uix.filechooser import FileChooserListView
from kivy.uix.popup import Popup
from kivy.uix.modalview import ModalView
from kivy.uix.boxlayout import BoxLayout
from kivy.uix.label import Label
from kivy.uix.button import Button
from datetime import datetime
import asyncio
import threading
import os
import time


# ============================================================
# 🧑‍💼 ADMIN CHAT SCREEN — ORGANIZED + FEATURE-COMPLETE
# ============================================================

from kivy.uix.screenmanager import Screen
from kivy.app import App
from kivy.clock import Clock
from kivy.lang import Builder
from kivy.metrics import dp, sp
from kivy.properties import ObjectProperty
from kivy.uix.modalview import ModalView
from kivy.uix.boxlayout import BoxLayout
from kivy.uix.floatlayout import FloatLayout
from kivy.uix.scrollview import ScrollView
from kivy.uix.gridlayout import GridLayout
from kivy.uix.button import Button
from kivy.uix.label import Label
from kivy.uix.filechooser import FileChooserListView
from kivy.uix.popup import Popup
from kivy.factory import Factory
from datetime import datetime
import asyncio
import threading
import os
import time


class AdminChatScreen(Screen):
    """Admin-only chat interface for sending messages to user groups."""

    backend = None
    current_user = None
    user_email = None
    available_groups = []
    current_chat_group = "all_users"
    pinned_messages = []
    message_poll_event = None
    emoji_picker = ObjectProperty(None, allownone=True)

    # ============================================================
    # 🔹 INITIALIZATION / SCREEN ENTRY
    # ============================================================
    def on_enter(self):
        """Initialize backend and begin polling messages."""
        try:
            app = App.get_running_app()
            self.backend = app.backend
            self.current_user = "admin001"  # TODO: dynamically pull from session
            self.user_email = "admin@clckenya.org"
            self.available_groups = [
                "all_users", "nairobi", "rift_valley", "coastal", "western", "central"]
            
            self.pending_attachments = []
            self.attachment_preview_area = self.ids.get("attachment_preview_area")
            print("🧑‍💼 AdminChatScreen initialized")

            self.load_messages()
            self.start_message_polling()
        except Exception as e:
            print(f"❌ on_enter error: {e}")

    def on_leave(self):
        """Stop background polling."""
        try:
            if self.message_poll_event:
                self.message_poll_event.cancel()
        except Exception as e:
            print(f"❌ on_leave cleanup error: {e}")

    def go_back(self):
        """Navigate back to dashboard."""
        try:
            if 'user_dashboard' in self.manager.screen_names:
                self.manager.current = 'user_dashboard'
            else:
                self.manager.current = 'admin_chat'
            print("⬅️ Back from AdminChatScreen")
        except Exception as e:
            print(f"Back navigation error: {e}")
            self.manager.current = 'login'
    # ============================================================
    # 📎 Pending attachments & helper
    # ============================================================
    

    def _guess_media_type(self, file_path):
        ext = file_path.lower()
        if ext.endswith((".jpg", ".jpeg", ".png", ".gif")):
            return "image"
        elif ext.endswith((".mp4", ".mov", ".avi")):
            return "video"
        elif ext.endswith((".mp3", ".wav")):
            return "audio"
        elif ext.endswith((".pdf", ".doc", ".docx", ".txt")):
            return "document"
        return "file"


    # ============================================================
    # ✉️ MESSAGE SENDING (updated)
    # ============================================================
    def send_message(self, linked_to=None):
        """
        Triggered by Send button — sends text + any pending attachments.
        If attachments exist, sends them with optional caption.
        """
        try:
            caption_text = self.ids.message_input.text.strip()
            files_to_send = getattr(self, "pending_attachments", [])

            if not caption_text and not files_to_send:
                return  # nothing to send

            # Clear input & preview immediately
            self.ids.message_input.text = ""
            if hasattr(self, "attachment_preview_area") and self.attachment_preview_area:
                self.attachment_preview_area.clear_widgets()
            self.pending_attachments = []

            # 1️⃣ Send all attachments (with optional caption)
            for file_path in files_to_send:
                media_type = self._guess_media_type(file_path)
                threading.Thread(
                    target=self._upload_media_async,
                    args=(file_path, media_type),
                    daemon=True
                ).start()

            # 2️⃣ If only text (no attachments), send as regular message
            if caption_text and not files_to_send:
                temp_msg = {
                    "id": f"local_{int(time.time() * 1000)}",
                    "sender_id": self.current_user,
                    "sender_name": "Admin",
                    "content": caption_text,
                    "timestamp": datetime.now().strftime("%H:%M"),
                    "status": "sending",
                    "message_type": "text",
                    "media_path": None,
                    "media_name": None,
                }

                # Add message immediately to UI
                self.add_message_card(temp_msg)
                self.scroll_to_bottom()

                # Launch backend send
                threading.Thread(
                    target=self._send_async,
                    args=(caption_text, linked_to),
                    daemon=True
                ).start()

        except Exception as e:
            print(f"❌ send_message error: {e}")




    def _send_async(self, content, linked_to=None):
        """Async send message to backend."""
        try:
            async def do_send():
                result = await self.backend.send_message(
                    content=content,
                    sender_id=self.current_user,
                    sender_name="Admin",
                    target_groups=[self.current_chat_group],
                    media_path=None,
                    media_type="text",
                    linked_to=linked_to
                )

                if result:
                    print("✅ Text message sent to backend")
                    Clock.schedule_once(lambda dt: self.load_messages(), 1)

            loop = asyncio.new_event_loop()
            asyncio.set_event_loop(loop)
            loop.run_until_complete(do_send())
            loop.close()

        except Exception as e:
            print(f"❌ send_async failed: {e}")



        # ============================================================
        # 🔄 MESSAGE FETCHING / POLLING
        # ============================================================
        def start_message_polling(self):
            """Poll messages every 10 seconds."""
            try:
                if self.message_poll_event:
                    self.message_poll_event.cancel()

                self.message_poll_event = Clock.schedule_interval(lambda dt: self.load_messages(), 10)
                print("🔁 Started message polling")
            except Exception as e:
                print(f"Polling start error: {e}")

    def load_messages(self):
        """Load messages asynchronously from backend."""
        try:
            def background_fetch():
                try:
                    async def get_msgs():
                        msgs = await self.backend.get_messages([self.current_chat_group])
                        if msgs:
                            # Normalize data types before rendering
                            for m in msgs:
                                # Ensure read_by is an array
                                read_by = m.get("read_by", [])
                                if isinstance(read_by, str):
                                    try:
                                        read_by = json.loads(read_by)
                                    except Exception:
                                        read_by = []
                                m["read_by"] = read_by

                                # Ensure timestamp is numeric (convert ms → s)
                                ts_value = m.get("timestamp", time.time())
                                try:
                                    ts_value = float(ts_value)
                                    # 🔧 FIX: convert milliseconds → seconds
                                    if ts_value > 1e11:  
                                        ts_value /= 1000
                                except Exception:
                                    ts_value = time.time()
                                m["timestamp"] = ts_value

                            Clock.schedule_once(lambda dt: self.render_messages(msgs), 0)

                    loop = asyncio.new_event_loop()
                    asyncio.set_event_loop(loop)
                    loop.run_until_complete(get_msgs())
                    loop.close()
                except Exception as e:
                    print(f"Error loading messages: {e}")

            threading.Thread(target=background_fetch, daemon=True).start()

        except Exception as e:
            print(f"load_messages error: {e}")


    def render_messages(self, messages):
        """Render or update messages incrementally without wiping the UI."""
        try:
            container = self.ids.message_container
            existing_cards = {
                child.message_id: child
                for child in container.children
                if hasattr(child, "message_id")
            }

            # Build index for linking captions
            msg_index = {m.get("$id"): m for m in messages}

            # Sort oldest → newest
            messages_sorted = sorted(messages, key=lambda m: m.get("timestamp", 0))
            seen_ids = set()

            for msg in messages_sorted:
                msg_id = msg.get("$id", "")
                seen_ids.add(msg_id)
                msg_type = msg.get("message_type", "text")
                linked_to = msg.get("linked_to")

                # Handle captions linked to media
                if linked_to and linked_to in msg_index:
                    msg_index[linked_to]["caption_text"] = msg.get("content", "")
                    continue

                # Format timestamp safely
                ts_value = msg.get("timestamp", time.time())
                try:
                    ts_value = float(ts_value)
                    if ts_value > 1e11:  # milliseconds → seconds
                        ts_value /= 1000
                    formatted_time = datetime.fromtimestamp(ts_value).strftime("%H:%M")
                except Exception:
                    formatted_time = datetime.now().strftime("%H:%M")

                msg_dict = {
                    "id": msg_id,
                    "sender_id": msg.get("sender_id", ""),
                    "sender_name": msg.get("sender_name", ""),
                    "content": msg.get("content", msg.get("caption_text", "")),
                    "timestamp": formatted_time,
                    "status": msg.get("status", "delivered"),
                    "message_type": msg_type,
                    "media_path": msg.get("media_path"),
                    "media_name": os.path.basename(msg.get("media_path"))
                    if msg.get("media_path")
                    else None,
                }

                # ✅ Update or create cards
                if msg_id in existing_cards:
                    card = existing_cards[msg_id]
                    if card.status != msg_dict["status"]:
                        card.status = msg_dict["status"]
                        if hasattr(card, "tick_label"):
                            card.tick_label.text = card.tick_icon
                            card.tick_label.color = card.tick_color
                else:
                    print(f"🆕 Adding new message card {msg_id}")
                    self.add_message_card(msg_dict)

                # ✅ Mark as read when user sees it (if from another sender)
                if (
                    msg_dict["sender_id"] != self.current_user
                    and msg_dict["status"] != "read"
                    and self.backend.online_mode
                ):
                    threading.Thread(
                        target=lambda: asyncio.run(
                            self.backend.mark_message_as_read(msg_dict["id"], self.current_user)
                        ),
                        daemon=True,
                    ).start()

            # 🚫 Do not remove old cards (prevents flicker)
            self.scroll_to_bottom()

        except Exception as e:
            print(f"render_messages error: {e}")
    # ============================================================
    # 🧱 MESSAGE CARD CREATION
    # ============================================================
    def add_message_card(self, msg):
        """Create AdminMessageCard widget dynamically."""
        try:
            widget_cls = getattr(Factory, "AdminMessageCard", None)
            if not widget_cls:
                print("❌ Unknown <AdminMessageCard> in KV")
                return

            # remap fields
            msg["content_text"] = msg.pop("content", "")
            card = widget_cls()

            for k, v in msg.items():
                try:
                    setattr(card, k, v)
                except Exception:
                    pass

            self.ids.message_container.add_widget(card)

        except Exception as e:
            print(f"❌ add_message_card error: {e}")

    def scroll_to_bottom(self):
        """Auto-scroll to newest message."""
        try:
            self.ids.scroll_view.scroll_y = 0
        except Exception:
            pass

    # ============================================================
    # 😊 EMOJI PICKER
    # ============================================================
    def open_emoji_picker(self):
        """Open floating emoji picker above input bar."""
        try:
            if self.emoji_picker:
                self.close_emoji_picker()
                return

            emojis = [
                # 😀 faces + gestures + symbols (shortened list for brevity)
                "😀","😁","😂","🤣","😃","😄","😅","😉","😊","😍","😘","😎","🤔","😏","😢","😭","😤","😡","🤬",
                "👋","👌","👍","👎","👏","🙏","💪","❤️","💙","💚","💛","💜","🖤","💔","💞","💕","💖","💘","💝","💥",
                "⭐","🌈","🔥","💧","🍀","🌹","🌸","🎉","🎁","🎈","💡","⚡","💻","📱","👀","👂","🧠"
            ]

            grid = GridLayout(cols=8, spacing=5, padding=5, size_hint_y=None)
            grid.bind(minimum_height=grid.setter("height"))

            for emoji in emojis:
                btn = Button(
                    text=emoji, font_size=24,
                    size_hint=(None, None), size=(48, 48),
                    background_normal='', background_down='',
                    background_color=(0.05, 0.05, 0.05, 1),
                    color=(0, 1, 0.4, 1)
                )
                btn.bind(on_press=lambda instance, e=emoji: self.insert_emoji(e))
                grid.add_widget(btn)

            scroll = ScrollView(size_hint=(1, None), height=dp(220), bar_width=dp(6))
            scroll.add_widget(grid)

            overlay = FloatLayout(size_hint=(1, None), height=dp(220))
            overlay.add_widget(scroll)
            overlay.pos = (0, self.ids.input_bar.top)

            self.add_widget(overlay)
            self.emoji_picker = overlay

        except Exception as e:
            print(f"emoji_picker error: {e}")

    def close_emoji_picker(self):
        """Close emoji overlay."""
        if self.emoji_picker:
            self.remove_widget(self.emoji_picker)
            self.emoji_picker = None

    def insert_emoji(self, emoji):
        """Insert emoji into text input."""
        self.ids.message_input.text += emoji
        self.close_emoji_picker()

    # ============================================================
    # 📎 ATTACHMENTS
    # ============================================================
    from kivy.uix.popup import Popup
    from kivy.uix.boxlayout import BoxLayout
    from kivy.uix.filechooser import FileChooserListView
    from kivy.uix.button import Button
    from kivy.metrics import dp
    from kivy.uix.label import Label
    from kivy.uix.image import Image
    from kivy.utils import platform
    import os


    def open_attachment_picker(self):
        from kivy.utils import platform
        """Open a categorized and styled file picker popup for selecting multiple attachments."""
        try:
            # 🌍 Determine top-level path depending on platform
            if platform == "android":
                base_path = "/storage/emulated/0/"  # Android root (user-accessible)
            elif platform in ("win", "linux", "macosx"):
                base_path = "C:/" if os.name == "nt" else os.path.expanduser("~")
            else:
                base_path = os.path.expanduser("~")

            # 📂 Define allowed file types
            file_filters = [
                "*.jpg", "*.jpeg", "*.png", "*.gif",
                "*.mp4", "*.mov", "*.avi",
                "*.mp3", "*.wav",
                "*.pdf", "*.doc", "*.docx", "*.txt"
            ]

            # 🗂️ Create file chooser
            fc = FileChooserListView(
                path=base_path,
                filters=file_filters,
                multiselect=True,
                dirselect=False
            )

            # ✅ Add readable labels for file categories
            category_bar = BoxLayout(
                size_hint_y=None,
                height=dp(40),
                spacing=dp(5),
                padding=[dp(5), dp(5)]
            )

            categories = {
                "🖼️ Images": ["*.jpg", "*.jpeg", "*.png", "*.gif"],
                "🎥 Videos": ["*.mp4", "*.mov", "*.avi"],
                "🎧 Audio": ["*.mp3", "*.wav"],
                "📄 Documents": ["*.pdf", "*.doc", "*.docx", "*.txt"],
                "📁 All": file_filters
            }

            def apply_filter(f_patterns):
                fc.filters = f_patterns
                fc._update_files()

            for label_text, patterns in categories.items():
                btn = Button(
                    text=label_text,
                    font_size="13sp",
                    size_hint_x=None,
                    width=dp(100),
                    background_color=(0.1, 0.6, 1, 1),
                    color=(1, 1, 1, 1),
                    on_release=lambda btn, p=patterns: apply_filter(p)
                )
                category_bar.add_widget(btn)

            # 🔘 Bottom buttons
            btn_layout = BoxLayout(size_hint_y=None, height=dp(50), spacing=dp(10), padding=[dp(10), dp(5)])

            btn_cancel = Button(
                text="❌ Cancel",
                background_color=(0.3, 0.3, 0.3, 1),
                color=(1, 1, 1, 1)
            )

            def select_files(instance):
                if not fc.selection:
                    print("⚠️ No files selected.")
                    return

                selected_files = fc.selection
                popup.dismiss()

                print(f"📎 Selected {len(selected_files)} attachments:")
                for f in selected_files:
                    print("   •", f)

                # Store multiple files
                self.pending_attachments = selected_files

                # 🔍 Update preview area
                if hasattr(self, 'attachment_preview_area'):
                    self.attachment_preview_area.clear_widgets()

                    for file_path in selected_files:
                        file_name = os.path.basename(file_path)

                        if file_path.lower().endswith((".jpg", ".jpeg", ".png", ".gif")):
                            thumb = Image(source=file_path, size_hint=(None, None), size=(dp(60), dp(60)))
                            self.attachment_preview_area.add_widget(thumb)
                        else:
                            label = Label(
                                text=f"📄 {file_name}",
                                color=(0, 0, 0, 1),
                                font_size='14sp',
                                size_hint_x=None,
                                width=dp(200)
                            )
                            self.attachment_preview_area.add_widget(label)

                    print("✅ Attachments preview added — awaiting send.")

            btn_select = Button(
                text="📂 Attach",
                background_color=(0.1, 0.7, 0.3, 1),
                color=(1, 1, 1, 1),
                on_release=select_files
            )

            btn_cancel.bind(on_release=lambda *_: popup.dismiss())

            btn_layout.add_widget(btn_cancel)
            btn_layout.add_widget(btn_select)

            # 🪟 Combine layout
            content = BoxLayout(orientation="vertical", spacing=dp(5))
            content.add_widget(category_bar)
            content.add_widget(fc)
            content.add_widget(btn_layout)

            popup = Popup(
                title="📎 Select Files to Attach",
                content=content,
                size_hint=(0.95, 0.9),
                auto_dismiss=False
            )
            popup.open()

        except Exception as e:
            print(f"[⚠️ ERROR] Attachment picker failed: {e}")




    def _upload_media_async(self, file_path, media_type):
        """Upload media and optionally send a caption linked to it."""
        try:
            caption_text = self.ids.message_input.text.strip()
            self.ids.message_input.text = ""  # clear input

            async def do_upload():
                # Step 1️⃣ Send the media itself
                media_doc = await self.backend.send_message(
                    content="",
                    sender_id=self.current_user,
                    sender_name="Admin",
                    target_groups=[self.current_chat_group],
                    media_path=file_path,
                    media_type=media_type
                )

                media_message_id = media_doc.get("$id") if media_doc else None

                # Step 2️⃣ If caption exists, send it as linked message
                if caption_text and media_message_id:
                    await self.backend.send_message(
                        content=caption_text,
                        sender_id=self.current_user,
                        sender_name="Admin",
                        target_groups=[self.current_chat_group],
                        media_path=None,
                        media_type="text",
                        linked_to=media_message_id
                    )

                # Step 3️⃣ Refresh UI
                Clock.schedule_once(lambda dt: self.load_messages(), 1)

            loop = asyncio.new_event_loop()
            asyncio.set_event_loop(loop)
            loop.run_until_complete(do_upload())
            loop.close()

        except Exception as e:
            print(f"upload_media_async error: {e}")




        # ============================================================
        # 📌 PINNING / DELETING
        # ============================================================
    def pin_message(self, message_id):
        """Pin message locally."""
        try:
            if message_id not in [m["id"] for m in self.pinned_messages]:
                self.pinned_messages.append({"id": message_id, "title": "Pinned"})
                print(f"📌 Pinned message {message_id}")
        except Exception as e:
            print(f"pin_message error: {e}")

    def delete_message(self, message_id):
        """Delete message from backend."""
        try:
            async def do_delete():
                await self.backend.databases.delete_document(
                    database_id=self.backend.database_id,
                    collection_id=self.backend.messages_collection_id,
                    document_id=message_id
                )
                print(f"🗑️ Deleted message {message_id}")
                Clock.schedule_once(lambda dt: self.load_messages(), 1)

            loop = asyncio.new_event_loop()
            asyncio.set_event_loop(loop)
            loop.run_until_complete(do_delete())
            loop.close()
        except Exception as e:
            print(f"delete_message error: {e}")

    # ============================================================
    # ✅ MESSAGE STATS (ticks)
    # ============================================================
    def toggle_stats(self, message_id):
        """Toggle message stats visibility (read/delivered)."""
        try:
            card = self.ids.message_container.ids.get(message_id)
            if not card:
                return
            if hasattr(card, "stats_visible"):
                card.stats_visible = not card.stats_visible
        except Exception as e:
            print(f"toggle_stats error: {e}")

    # ============================================================
    # 👥 RECIPIENT SELECTION
    # ============================================================
    def open_recipient_selector(self):
        """Select which group(s) to message."""
        try:
            modal = ModalView(size_hint=(1, None), height=dp(300), background_color=(0, 0, 0, 0.7))
            layout = BoxLayout(orientation="vertical", padding=dp(12), spacing=dp(8))

            title = Label(text="Select Recipients", font_size=sp(18), color=(1, 1, 1, 1),
                          size_hint_y=None, height=dp(40))
            layout.add_widget(title)

            for group in self.available_groups:
                btn = Button(
                    text=group.upper(),
                    size_hint_y=None, height=dp(45),
                    background_color=(0.1, 0.1, 0.1, 1),
                    color=(0, 1, 0.3, 1),
                    on_release=lambda btn, g=group: self._select_recipient(g, modal)
                )
                layout.add_widget(btn)

            cancel = Button(
                text="Cancel", size_hint_y=None, height=dp(45),
                background_color=(0.15, 0.15, 0.15, 1),
                color=(1, 1, 1, 1),
                on_release=modal.dismiss
            )
            layout.add_widget(cancel)
            modal.add_widget(layout)
            modal.open()
        except Exception as e:
            print(f"open_recipient_selector error: {e}")

    def _select_recipient(self, group, modal):
        """Set the active recipient group."""
        modal.dismiss()
        self.current_chat_group = group
        print(f"👥 Selected group: {group}")


from kivy.uix.screenmanager import Screen
from kivy.app import App
from kivy.clock import Clock
from kivy.lang import Builder
from datetime import datetime
import asyncio
import threading
import os
import time

from kivy.uix.screenmanager import Screen
from kivy.app import App
from kivy.clock import Clock
from kivy.lang import Builder
from datetime import datetime
from kivy.metrics import dp, sp
import asyncio
import threading
import os
import time


class UserChatScreen(Screen):
    """Read-only chat view for normal users — displays only admin messages"""
    backend = None
    user_email = None
    current_user = None
    user_region = None
    periodic_update_event = None
    last_message_count = 0
    processed_messages = set()  # Track which messages we've already processed

    def on_enter(self):
        """When the screen loads"""
        try:
            app = App.get_running_app()
            self.backend = app.backend
            self.user_email = getattr(app, "user_email", "user@clckenya.org")
            self.current_user = getattr(app, "user_id", "user_001")
            self.user_region = getattr(app, "user_region", "nairobi")

            print(f"👤 Entered UserChatScreen for {self.user_email} ({self.user_region})")

            # Update status
            self.update_status("Loading messages...")
            self.ids.last_update_label.text = datetime.now().strftime("%H:%M")
            
            # Load messages
            self.load_messages()
            self.start_polling()
            
        except Exception as e:
            print(f"❌ UserChatScreen on_enter error: {e}")
            self.update_status("Error loading messages")

    def update_status(self, message):
        """Helper method to update status label"""
        try:
            self.ids.status_label.text = message
        except Exception as e:
            print(f"Status update error: {e}")

    def go_back(self):
        try:
            self.manager.current = 'user_dashboard'
            print("⬅️ Back to dashboard from UserChat")
        except Exception as e:
            print(f"Back navigation error: {e}")
            self.manager.current = 'login'

    def on_leave(self):
        """Stop periodic updates"""
        try:
            if self.periodic_update_event:
                self.periodic_update_event.cancel()
                self.periodic_update_event = None
            print("👋 Left UserChatScreen")
        except Exception as e:
            print(f"❌ UserChatScreen on_leave error: {e}")

    def load_messages(self):
        """Fetch messages from AppWrite (async in thread)"""
        try:
            def background_fetch():
                try:
                    async def get_msgs():
                        msgs = await self.backend.get_messages(["all_users", self.user_region])
                        if msgs:
                            # Filter only admin messages and sort by timestamp
                            admin_msgs = [
                                m for m in msgs
                                if m.get("sender_name", "").lower() == "admin" or 
                                   "admin" in m.get("sender_id", "").lower()
                            ]
                            # Sort by timestamp (newest first for display)
                            admin_msgs.sort(key=lambda m: m.get("timestamp", 0), reverse=True)
                            
                            # Update message statuses for new messages
                            await self.update_message_statuses(admin_msgs)
                            
                            Clock.schedule_once(lambda dt: self.render_messages(admin_msgs), 0)
                        else:
                            Clock.schedule_once(lambda dt: self.show_no_messages(), 0)

                    loop = asyncio.new_event_loop()
                    asyncio.set_event_loop(loop)
                    loop.run_until_complete(get_msgs())
                    loop.close()
                except Exception as e:
                    print(f"❌ Error fetching messages: {e}")
                    Clock.schedule_once(lambda dt: self.update_status("Connection error"), 0)

            threading.Thread(target=background_fetch, daemon=True).start()
        except Exception as e:
            print(f"❌ load_messages error: {e}")
            self.update_status("Load error")

    async def update_message_statuses(self, messages):
        """Update message statuses (sent → delivered → read) for current user."""
        try:
            loop = asyncio.get_event_loop()

            for msg in messages:
                message_id = msg.get("$id")
                if not message_id:
                    continue

                # Skip if we've already processed this message
                if message_id in self.processed_messages:
                    continue

                sender_id = msg.get("sender_id", "")
                current_user_id = self.current_user

                # Only update status for messages not sent by the current user
                if sender_id != current_user_id:
                    current_status = msg.get("status", "sent")
                    read_by = msg.get("read_by", [])

                    # Normalize `read_by`
                    if isinstance(read_by, str):
                        try:
                            read_by = json.loads(read_by)
                        except Exception:
                            read_by = []
                    elif not isinstance(read_by, list):
                        read_by = []

                    # ✅ Mark as delivered (if needed)
                    if current_status == "sent":
                        print(f"📨 Marking message {message_id} as delivered")
                        success = await loop.run_in_executor(
                            None, self.backend.update_message_status, message_id, "delivered"
                        )
                        if success:
                            msg["status"] = "delivered"

                    # ✅ Mark as read (if not already)
                    if current_user_id not in read_by:
                        print(f"👁️ Marking message {message_id} as read by {current_user_id}")
                        success = await loop.run_in_executor(
                            None, self.backend.mark_message_as_read, message_id, current_user_id
                        )
                        if success:
                            read_by.append(current_user_id)
                            msg["read_by"] = read_by
                            msg["status"] = "read"

                    # Cache this message ID so we don't reprocess it
                    self.processed_messages.add(message_id)

        except Exception as e:
            print(f"❌ Error updating message statuses: {e}")


    def render_messages(self, messages):
        """Render or update messages incrementally and update status ticks."""
        try:
            container = self.ids.message_container
            existing_cards = {
                child.message_id: child
                for child in container.children
                if hasattr(child, "message_id")
            }

            # Sort oldest → newest
            messages_sorted = sorted(messages, key=lambda m: m.get("timestamp", 0))
            seen_ids = set()

            for msg in messages_sorted:
                msg_id = msg.get("$id", "")
                seen_ids.add(msg_id)

                # Skip if we already displayed this message and it's unchanged
                if msg_id in existing_cards:
                    card = existing_cards[msg_id]
                    # Update ticks if status changed
                    new_status = msg.get("status", "delivered")
                    if hasattr(card, "status") and card.status != new_status:
                        card.status = new_status
                        if hasattr(card, "tick_label"):
                            card.tick_label.text = card.tick_icon
                            card.tick_label.color = card.tick_color
                    continue

                # Safe timestamp formatting
                ts_value = msg.get("timestamp", time.time())
                try:
                    ts_value = float(ts_value)
                    if ts_value > 1e11:  # milliseconds → seconds
                        ts_value /= 1000
                    formatted_time = datetime.fromtimestamp(ts_value).strftime("%H:%M")
                except Exception:
                    formatted_time = datetime.now().strftime("%H:%M")

                msg_dict = {
                    "id": msg_id,
                    "sender_id": msg.get("sender_id", ""),
                    "sender_name": msg.get("sender_name", ""),
                    "content": msg.get("content", ""),
                    "timestamp": formatted_time,
                    "status": msg.get("status", "delivered"),
                    "message_type": msg.get("message_type", "text"),
                    "media_path": msg.get("media_path"),
                    "media_name": os.path.basename(msg.get("media_path"))
                    if msg.get("media_path")
                    else None,
                }

                # Add new message card
                self.add_message_card(msg_dict)
                print(f"🆕 Added message card {msg_id}")

                # ✅ Immediately mark as read if visible and not sent by current user
                if (
                    msg_dict["sender_id"] != self.current_user
                    and msg_dict["status"] != "read"
                    and self.backend.online_mode
                ):
                    threading.Thread(
                        target=lambda: asyncio.run(
                            self.backend.mark_message_as_read(msg_dict["id"], self.current_user)
                        ),
                        daemon=True,
                    ).start()

            # Update stats on screen
            delivered_count = sum(1 for msg in messages if msg.get("status") in ["delivered", "read"])
            read_count = sum(1 for msg in messages if msg.get("status") == "read")

            status_text = f"{len(messages)} announcements"
            if delivered_count > 0:
                status_text += f" • {delivered_count} delivered"
            if read_count > 0:
                status_text += f" • {read_count} read"

            self.update_status(status_text)
            self.ids.last_update_label.text = datetime.now().strftime("%H:%M")
            self.scroll_to_bottom()

        except Exception as e:
            print(f"❌ render_messages error: {e}")
            self.update_status("Render error")


    def show_no_messages(self):
        """Show message when no announcements available"""
        try:
            container = self.ids.message_container
            container.clear_widgets()
            
            no_msg_layout = BoxLayout(
                orientation='vertical',
                size_hint_y=None,
                height=dp(200),
                padding=[dp(20), dp(20)]
            )
            
            with no_msg_layout.canvas.before:
                Color(0.1, 0.1, 0.1, 0.7)
                RoundedRectangle(
                    pos=no_msg_layout.pos,
                    size=no_msg_layout.size,
                    radius=[dp(15),]
                )
            
            icon = Label(
                text='📭',
                font_size=sp(40),
                color=(0.949, 0.788, 0.298, 1),
                size_hint_y=None,
                height=dp(60)
            )
            
            text = Label(
                text='No announcements yet\nCheck back later for updates',
                font_size=sp(16),
                color=(1, 1, 1, 0.9),
                halign='center',
                size_hint_y=None,
                height=dp(80)
            )
            
            no_msg_layout.add_widget(icon)
            no_msg_layout.add_widget(text)
            container.add_widget(no_msg_layout)
            
            self.update_status("No messages")
            
        except Exception as e:
            print(f"Error showing no messages: {e}")

    def add_message_card(self, msg):
        """Adds one UserMessageCard with proper data formatting"""
        try:
            # Convert timestamp
            ts = msg.get("timestamp", time.time())
            if isinstance(ts, (int, float)):
                # Handle both seconds and milliseconds
                if ts > 1e11:  # Likely milliseconds
                    ts = ts / 1000
                ts_str = datetime.fromtimestamp(ts).strftime("%b %d, %H:%M")
            else:
                try:
                    ts_str = datetime.fromisoformat(ts.replace('Z', '+00:00')).strftime("%b %d, %H:%M")
                except Exception:
                    ts_str = "Recent"
            
            # Handle message type and content
            message_type = msg.get("message_type", "text")
            content = msg.get("content", "")
            media_path = msg.get("media_path")
            
            # Add delivery status indicator
            status = msg.get("status", "sent")
            read_by = msg.get("read_by", [])
            if isinstance(read_by, str):
                try:
                    read_by = json.loads(read_by)
                except:
                    read_by = []
            
            # Add status indicator to content
            status_indicator = ""
            if status == "read":
                status_indicator = " 👁️"
            elif status == "delivered":
                status_indicator = " ✓✓"
            elif status == "sent":
                status_indicator = " ✓"
            
            # If it's a caption for media, adjust display
            if msg.get("linked_to") and media_path:
                content = f"📎 {content}" if content else "📎 Media attachment"
            
            # Use Factory to create the dynamic class
            from kivy.factory import Factory
            card = Factory.UserMessageCard()
            
            # Set properties
            card.message_type = message_type
            card.content = content + status_indicator
            card.sender_name = msg.get("sender_name", "Admin")
            card.timestamp = ts_str
            card.media_path = media_path
            card.media_name = os.path.basename(media_path) if media_path else None
            
            self.ids.message_container.add_widget(card)
            
        except Exception as e:
            print(f"❌ add_message_card error: {e}")

    def scroll_to_bottom(self):
        """Auto-scroll to newest message (top of reversed list)"""
        try:
            # Since we display newest first, scroll to top (index 0)
            self.ids.scroll_view.scroll_y = 1.0
        except Exception as e:
            print(f"Scroll error: {e}")

    def start_polling(self):
        """Automatically refresh messages with status updates"""
        try:
            if self.periodic_update_event:
                self.periodic_update_event.cancel()

            def refresh(dt):
                self.update_status("Checking for updates...")
                self.load_messages()

            self.periodic_update_event = Clock.schedule_interval(refresh, 30)  # Every 30 seconds
            print("🔁 Started user chat polling every 30s")
            
        except Exception as e:
            print(f"❌ start_polling error: {e}")

    def logout_user(self):
        """Logout user"""
        try:
            print("🚪 Logging out from UserChat...")
            db = DatabaseManager()
            db.logout_current_user()
            self.manager.current = "login"
        except Exception as e:
            print(f"Logout error: {e}")


# ADD SETTINGS SCREEN CLASS AFTER ChatScreen
from kivy.uix.screenmanager import Screen
from kivy.properties import BooleanProperty, StringProperty, ListProperty
from kivy.clock import Clock
from kivy.app import App
from kivy.metrics import dp, sp
from kivy.uix.boxlayout import BoxLayout
from kivy.uix.button import Button
from kivy.uix.label import Label
from kivy.uix.widget import Widget

# You’ll implement DatabaseManager later
#from database_manager import DatabaseManager  


class SettingsRouter(Screen):
    """Router that checks user role and redirects to Admin or User settings."""
    
    def on_enter(self):
        """Check user role and route to the appropriate screen."""
        try:
            app = App.get_running_app()
            db = DatabaseManager()
            
            # Simulate fetching logged-in user
            current_user = db.get_current_user()  # You’ll define this
            if not current_user:
                print("⚠️ No user logged in, returning to login screen")
                self.manager.current = "login"
                return

            if current_user.get("is_admin"):
                print("➡ Redirecting to Admin Settings")
                self.manager.current = "admin_settings"
            else:
                print("➡ Redirecting to User Settings")
                self.manager.current = "user_settings"

        except Exception as e:
            print(f"Error routing to settings: {e}")
            self.manager.current = "login"


from kivy.app import App
from kivy.uix.boxlayout import BoxLayout
from kivy.uix.button import Button
from kivy.uix.label import Label
from kivy.uix.image import AsyncImage
from kivy.uix.popup import Popup
from kivy.uix.video import Video
from kivy.properties import StringProperty, ListProperty, BooleanProperty
from kivy.clock import Clock
from kivy.metrics import dp
from kivy.uix.behaviors import ButtonBehavior


class AdminMessageCard(ButtonBehavior, BoxLayout):
    # -------------------------
    # Message properties
    # -------------------------
    message_id = StringProperty("")
    message_type = StringProperty("text")  # text | image | video | document
    content_text = StringProperty("")
    caption_text = StringProperty("")
    media_path = StringProperty("")
    media_name = StringProperty("")
    timestamp = StringProperty("")
    status = StringProperty("sent")  # sent | delivered | read
    tick_icon = StringProperty("")
    tick_color = ListProperty([0.5, 0.5, 0.5, 1])

    # -------------------------
    # Internal state
    # -------------------------
    stats_visible = BooleanProperty(False)
    long_press_time = 0.5
    _press_clock = None

    # -------------------------
    # Event hooks
    # -------------------------
    def on_pin(self):
        """Triggered when user pins this message."""
        print(f"📌 [PIN] Message {self.message_id} pinned")

    def on_delete(self):
        """Triggered when user deletes this message."""
        print(f"🗑️ [DELETE] Message {self.message_id} deleted")

    # -------------------------
    # Initialization
    # -------------------------
    
    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        print(f"🧩 [INIT] AdminMessageCard({self.message_id}) created with status='{self.status}'")

        self.orientation = "vertical"
        self.size_hint_y = None
        self.height = self.minimum_height
        self.padding = dp(10)
        self.spacing = dp(8)
        self._ui_built = False

        # Bind status changes to tick updater
        self.bind(status=self._on_status_change)

        # Build UI once
        Clock.schedule_once(self._build_ui, 0.05)


    

    # -------------------------
    # Tick / status handling
    # -------------------------
    def _on_status_change(self, value):
        """
        Called whenever a message's delivery status changes.
        Updates the tick icon and color safely and ensures it stays visible.
        Uses the tick_label and footer defined in the KV file.
        """
        print(f"🔄 [STATUS_CHANGE] Message {self.message_id}: new status='{value}'")

        # --- Decide tick icon and color ---
        if value == "sent":
            self.tick_icon = "✓"
            self.tick_color = [0.6, 0.6, 0.6, 1]  # gray
        elif value == "delivered":
            self.tick_icon = "✓✓"
            self.tick_color = [0.6, 0.6, 0.6, 1]  # gray
        elif value == "read":
            self.tick_icon = "✓✓"
            self.tick_color = [0.1, 0.6, 1, 1]    # blue
        else:
            print(f"⚠️ [STATUS_CHANGE] Unknown status '{value}' for {self.message_id}")
            return

        print(f"🧾 [STATUS_CHANGE] -> Tick icon='{self.tick_icon}', color={self.tick_color}")

        # --- Update tick label from KV ---
        tick_label = getattr(self.ids, "tick_label", None)
        if tick_label:
            tick_label.text = self.tick_icon
            tick_label.color = self.tick_color
            tick_label.opacity = 1
            tick_label.disabled = False

            # Debug print to confirm updates
            print(f"🎯 [STATUS_CHANGE] Updated KV tick_label for {self.message_id}")
        else:
            print(f"⚠️ [STATUS_CHANGE] tick_label not found in ids for {self.message_id}")

        # --- Request redraws to ensure UI updates immediately ---
        if tick_label:
            tick_label.canvas.ask_update()
            parent = tick_label.parent
            if parent:
                parent.canvas.ask_update()
                parent.do_layout()

        self.canvas.ask_update()

        print(f"✅ [STATUS_CHANGE] Finalized visual update for {self.message_id}")



    # -------------------------
    # UI construction
    # -------------------------
    
    
    def _build_ui(self, *args):
        """
        Builds or refreshes the message UI by updating KV-bound properties.
        No dynamic widget creation — the KV layout handles structure.
        """
        from kivy.clock import Clock

        # Prevent recursion
        if getattr(self, "_ui_building", False):
            print(f"🚫 [BUILD_UI] Reentry prevented for {self.message_id}")
            return
        self._ui_building = True

        print(f"🏗️ [BUILD_UI] Building UI for message {self.message_id}")

        # --- Update text content ---
        text = self.caption_text if getattr(self, "caption_text", None) else self.content_text
        self.content_text = text or ""

        # --- Update media path and type ---
        if getattr(self, "media_path", None):
            if self.message_type == "image":
                print(f"🖼️ [BUILD_UI] Preparing image for {self.message_id}")
            elif self.message_type == "video":
                print(f"🎞️ [BUILD_UI] Preparing video for {self.message_id}")
        else:
            print(f"📭 [BUILD_UI] No media attached for {self.message_id}")

        # --- Update footer fields ---
        self.timestamp = getattr(self, "timestamp", "")
        self.tick_icon = getattr(self, "tick_icon", "")
        self.tick_color = getattr(self, "tick_color", [0.5, 0.5, 0.5, 1])

        # Force KV to refresh visible bindings
        if "tick_label" in self.ids:
            tick_label = self.ids.tick_label
            tick_label.text = self.tick_icon or "✓"
            tick_label.color = self.tick_color
            tick_label.opacity = 1
            print(f"✅ [BUILD_UI] Updated tick_label in KV for {self.message_id}")
        else:
            print(f"⚠️ [BUILD_UI] tick_label not found in ids for {self.message_id}")

        # --- Trigger status-based visuals (✓, ✓✓, blue color, etc.) ---
        Clock.schedule_once(lambda dt: self._on_status_change(self.status), 0)

        # --- Finalize ---
        self._ui_built = True
        self._ui_building = False
        print(f"🎯 [BUILD_UI] Finalized UI build for {self.message_id}")

    # -------------------------
    # Media viewer
    # -------------------------
    def _on_media_touch(self, instance, touch):
        if instance.collide_point(*touch.pos):
            print(f"👆 [MEDIA_TOUCH] Opening viewer for {self.media_path}")
            self.open_media_viewer()

    def open_media_viewer(self):
        if not self.media_path:
            print(f"⚠️ [MEDIA_VIEWER] No media for message {self.message_id}")
            return
        layout = BoxLayout(orientation="vertical", padding=dp(10), spacing=dp(10))
        viewer = None
        if self.message_type == "image":
            viewer = AsyncImage(source=self.media_path, allow_stretch=True, keep_ratio=True)
        elif self.message_type == "video":
            viewer = Video(source=self.media_path, state="play", options={"eos": "loop"}, allow_stretch=True)
        if viewer:
            layout.add_widget(viewer)
        close_btn = Button(
            text="Close",
            size_hint_y=None,
            height=dp(45),
            background_color=(0.1, 0.1, 0.1, 1),
            color=(1, 1, 1, 1)
        )
        popup = Popup(
            title=self.media_name or "Media Viewer",
            content=layout,
            size_hint=(0.95, 0.9),
            background_color=(0, 0, 0, 0.8),
            auto_dismiss=False
        )
        close_btn.bind(on_release=lambda *_: popup.dismiss())
        layout.add_widget(close_btn)
        popup.open()
        print(f"📸 [MEDIA_VIEWER] Popup opened for {self.media_path}")

    # -------------------------
    # Long press / right-click
    # -------------------------
    def on_touch_down(self, touch):
        if self.collide_point(*touch.pos):
            if 'button' in touch.profile and touch.button == "right":
                self._show_context_menu()
                return True
            self._press_clock = Clock.schedule_once(lambda dt: self._show_context_menu(), self.long_press_time)
        return super().on_touch_down(touch)

    def on_touch_up(self, touch):
        if self._press_clock:
            self._press_clock.cancel()
            self._press_clock = None
        return super().on_touch_up(touch)

    # -------------------------
    # Context menu
    # -------------------------
    def _show_context_menu(self):
        print(f"📋 [CONTEXT_MENU] Showing menu for message {self.message_id}")
        layout = BoxLayout(orientation="vertical", padding=dp(10), spacing=dp(8))
        pin_btn = Button(text="📌 Pin Message", size_hint_y=None, height=dp(40))
        del_btn = Button(text="🗑️ Delete Message", size_hint_y=None, height=dp(40))
        cancel_btn = Button(text="Cancel", size_hint_y=None, height=dp(40))
        layout.add_widget(pin_btn)
        layout.add_widget(del_btn)
        layout.add_widget(cancel_btn)
        popup = Popup(
            title="Message Options",
            content=layout,
            size_hint=(None, None),
            size=(dp(200), dp(200)),
            background_color=(0, 0, 0, 0.85),
            auto_dismiss=True
        )

        pin_btn.bind(on_release=lambda *_: self._pin(popup))
        del_btn.bind(on_release=lambda *_: self._delete(popup))
        cancel_btn.bind(on_release=popup.dismiss)
        popup.open()

    def _pin(self, popup):
        popup.dismiss()
        print(f"📌 [ACTION] Pinning message {self.message_id}")
        self.on_pin()

    def _delete(self, popup):
        popup.dismiss()
        print(f"🗑️ [ACTION] Deleting message {self.message_id}")
        self.on_delete()





from kivy.uix.screenmanager import Screen
from kivy.properties import ListProperty
from kivy.metrics import dp, sp
from kivy.clock import Clock
from kivy.uix.boxlayout import BoxLayout
from kivy.uix.label import Label
from kivy.uix.button import Button

# Ensure DatabaseManager is imported from your database handler module
#from database_manager import DatabaseManager


class AdminSettingsScreen(Screen):
    """Admin Settings screen: manage users and logout."""

    users = ListProperty([])

    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        self.db_manager = DatabaseManager()
        self.current_user = None

    def on_enter(self):
        """Load all users and current admin info."""
        try:
            self.current_user = self.db_manager.get_current_user()
            if self.current_user:
                # ✅ Update the admin info label
                self.ids.current_user_info.text = (
                    f"👤 {self.current_user['name']}\n"
                    f"📧 {self.current_user['email']}\n"
                    f"📍 Region: {self.current_user.get('region', 'Nairobi')}\n"
                    f"👑 Role: Admin"
                )
            else:
                self.ids.current_user_info.text = "❌ Could not load admin details. Please log in again."
                print("⚠️ No current user found, redirecting to login...")
                Clock.schedule_once(lambda dt: setattr(self.manager, 'current', 'login'), 2)
                return

            # ✅ Load all users into the list
            self.load_all_users()

        except Exception as e:
            print(f"AdminSettingsScreen on_enter error: {e}")

    def load_all_users(self):
        """Fetch all users and display them."""
        try:
            users = self.db_manager.get_all_users()
            self.users = users
            users_list = self.ids.users_list
            users_list.clear_widgets()

            for user in users:
                self.add_user_to_list(user)

            print(f"✅ Loaded {len(users)} users in Admin panel")

        except Exception as e:
            print(f"Error loading users: {e}")

    def add_user_to_list(self, user):
        """Add user info row to the list with Font Awesome buttons."""
        layout = BoxLayout(
            orientation="horizontal",
            size_hint_y=None,
            height=dp(50),
            spacing=dp(10),
            padding=[dp(10), dp(5)]
        )

        # Background for user item
        with layout.canvas.before:
            Color(0.15, 0.15, 0.15, 0.7)
            layout.rect = RoundedRectangle(
                pos=layout.pos,
                size=layout.size,
                radius=[dp(8),]
            )
        layout.bind(pos=self._update_user_item_rect, size=self._update_user_item_rect)

        # User info (name and email)
        user_info_layout = BoxLayout(
            orientation="vertical",
            size_hint_x=0.6
        )
        
        user_name = Label(
            text=user['name'],
            font_size=sp(14),
            color=(1, 1, 1, 1),
            halign="left",
            valign="middle",
            text_size=(dp(200), None)
        )
        
        user_email = Label(
            text=user['email'],
            font_size=sp(11),
            color=(1, 1, 1, 0.7),
            halign="left",
            valign="middle",
            text_size=(dp(200), None)
        )
        
        user_info_layout.add_widget(user_name)
        user_info_layout.add_widget(user_email)

        # Role badge
        role_layout = BoxLayout(
            orientation="vertical",
            size_hint_x=0.2
        )
        
        role_icon = Label(
            text="👑" if user["is_admin"] else "👤",
            font_size=sp(16),
            color=(0.949, 0.788, 0.298, 1) if user["is_admin"] else (0.7, 0.7, 0.7, 1)
        )
        
        role_text = Label(
            text="Admin" if user["is_admin"] else "User",
            font_size=sp(10),
            color=(0.949, 0.788, 0.298, 1) if user["is_admin"] else (0.7, 0.7, 0.7, 1)
        )
        
        role_layout.add_widget(role_icon)
        role_layout.add_widget(role_text)

        # Action button - Font Awesome icons
        action_layout = BoxLayout(
            orientation="horizontal",
            size_hint_x=0.2,
            spacing=dp(5)
        )

        # Show action buttons only for other users, not current user
        if self.current_user and user["email"] != self.current_user["email"]:
            if user["is_admin"]:
                # Demote button (admin -> user)
                demote_btn = Button(
                    size_hint=(None, None),
                    size=(dp(35), dp(35)),
                    background_normal='',
                    background_color=(0.8, 0.2, 0.2, 1),
                    font_name='FontAwesomeSolid',
                    text='\uf506',  # user-minus icon
                    font_size=sp(14),
                    color=(1, 1, 1, 1),
                    on_press=lambda _, u=user: self.toggle_user_role(u)
                )
                action_layout.add_widget(demote_btn)
            else:
                # Promote button (user -> admin)
                promote_btn = Button(
                    size_hint=(None, None),
                    size=(dp(35), dp(35)),
                    background_normal='',
                    background_color=(0.2, 0.7, 0.2, 1),
                    font_name='FontAwesomeSolid',
                    text='\uf234',  # user-plus icon
                    font_size=sp(14),
                    color=(1, 1, 1, 1),
                    on_press=lambda _, u=user: self.toggle_user_role(u)
                )
                action_layout.add_widget(promote_btn)
        else:
            # Current user - show "You" indicator
            you_label = Label(
                text="You",
                font_size=sp(10),
                color=(0.2, 0.6, 1, 1),
                bold=True
            )
            action_layout.add_widget(you_label)

        # Add all components to main layout
        layout.add_widget(user_info_layout)
        layout.add_widget(role_layout)
        layout.add_widget(action_layout)
        
        self.ids.users_list.add_widget(layout)

    def _update_user_item_rect(self, instance, value):
        """Update the background rectangle position and size."""
        instance.rect.pos = instance.pos
        instance.rect.size = instance.size

    def toggle_user_role(self, user):
        """Promote or demote a user."""
        try:
            if user["is_admin"]:
                print(f"🔽 Demoting {user['name']}...")
                success = self.db_manager.demote_from_admin(user["id"])
                action = "demoted"
            else:
                print(f"⬆ Promoting {user['name']}...")
                success = self.db_manager.promote_to_admin(user["id"])
                action = "promoted"

            if success:
                print(f"✅ User {action} successfully.")
                # Show success feedback
                self.show_action_feedback(f"User {action} successfully!")
                # Reload the users list after a short delay
                Clock.schedule_once(lambda dt: self.load_all_users(), 0.5)
            else:
                print("❌ Failed to update role.")
                self.show_action_feedback("Failed to update user role.", is_error=True)

        except Exception as e:
            print(f"Error updating role: {e}")
            self.show_action_feedback("Error updating role.", is_error=True)

    def show_action_feedback(self, message, is_error=False):
        """Show feedback message for user actions."""
        try:
            if hasattr(self.ids, 'action_feedback'):
                feedback_label = self.ids.action_feedback
                feedback_label.text = message
                feedback_label.color = (1, 0, 0, 1) if is_error else (0, 1, 0, 1)
                feedback_label.opacity = 1
                
                # Fade out after 3 seconds
                Clock.schedule_once(lambda dt: setattr(feedback_label, 'opacity', 0), 3)
        except Exception as e:
            print(f"Error showing feedback: {e}")

    def promote_selected_user(self):
        """Legacy method - kept for KV compatibility."""
        print("ℹ️ Please use the promote button beside each user instead.")

    def demote_selected_user(self):
        """Legacy method - kept for KV compatibility."""
        print("ℹ️ Please use the demote button beside each user instead.")

    def logout_user(self):
        try:
            print("🚪 Logging out admin...")
            self.db_manager.logout_current_user()
            self.manager.current = "login"
        except Exception as e:
            print(f"Logout error: {e}")

    def go_back(self):
        try:
            self.manager.current = "user_dashboard"
            print("⬅️ Back to dashboard")
        except Exception as e:
            print(f"Back navigation error: {e}")
            self.manager.current = "login"

    def go_back_to_dashboard(self):
        """Alias for KV compatibility."""
        self.go_back()

class UserSettingsScreen(Screen):
    """Regular user settings screen."""

    def on_enter(self):
        """Display current user info."""
        try:
            db = DatabaseManager()
            user = db.get_current_user()

            if not user:
                print("⚠️ No user found, returning to login")
                self.manager.current = "login"
                return

            # Update the display with user information
            self.ids.current_user_info_user.text = (
                f"👤 {user['name']}\n"
                f"📧 {user['email']}\n"
                f"📍 Region: {user.get('region', 'nairobi')}\n"
                f"Role: User"
            )
        except Exception as e:
            print(f"User settings error: {e}")

    def logout_user(self):
        """Logout and go to login."""
        try:
            print("🚪 User logging out...")
            DatabaseManager().logout_current_user()
            self.manager.current = "login"
        except Exception as e:
            print(f"Logout error: {e}")

    def go_back(self):
        """Navigate back to dashboard."""
        try:
            self.manager.current = 'user_dashboard'
            print("Navigated back from User settings to dashboard")
        except Exception as e:
            print(f"Back navigation error: {e}")
            self.manager.current = 'login'

    def go_back_to_dashboard(self):
        """Alias for go_back to match KV file."""
        self.go_back()
class RegistrationScreen(Screen):
    occupation_field_visible = BooleanProperty(True)
    show_institutions = BooleanProperty(True)
    show_residence = BooleanProperty(False)
    
    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        self.db_manager = DatabaseManager()
        self.institutions = KenyanInstitutions.get_tertiary_institutions()
        Clock.schedule_once(self.initialize_form, 0.5)
    
    def initialize_form(self, dt):
        try:
            if hasattr(self, 'ids') and 'institution_spinner' in self.ids:
                self.ids.institution_spinner.values = self.institutions
                self.ids.institution_spinner.text = 'University of Nairobi'
                self.ids.occupation_spinner.text = 'Student'
                self.on_occupation_select()
                self.on_date_change()
                print("Form initialized successfully")
        except Exception as e:
            print(f"Initialization error: {e}")
    
    def on_date_change(self, *args):
        try:
            month = self.ids.month_spinner.text
            day = self.ids.day_spinner.text
            year = self.ids.year_spinner.text
            self.ids.date_display.text = f'Selected: {day} {month} {year}'
        except:
            pass
    
    def get_selected_date(self):
        try:
            month_map = {
                'Jan': '01', 'Feb': '02', 'Mar': '03', 'Apr': '04',
                'May': '05', 'Jun': '06', 'Jul': '07', 'Aug': '08',
                'Sep': '09', 'Oct': '10', 'Nov': '11', 'Dec': '12'
            }
            month = month_map.get(self.ids.month_spinner.text, '01')
            day = self.ids.day_spinner.text
            year = self.ids.year_spinner.text
            return f"{day}/{month}/{year}"
        except:
            return "01/01/2000"
    
    def validate_name(self):
        try:
            if not self.ids.name_input.text.strip():
                self.ids.name_error.text = "Name is required"
                return False
            self.ids.name_error.text = ""
            return True
        except:
            return False
    
    def validate_email(self):
        try:
            email = self.ids.email_input.text.strip()
            if not email:
                self.ids.email_error.text = "Email is required"
                return False
            if not ValidationUtils.validate_email(email):
                self.ids.email_error.text = "Invalid email format"
                return False
            self.ids.email_error.text = ""
            return True
        except:
            return False
    
    def validate_phone(self):
        try:
            phone = self.ids.phone_input.text.strip()
            if not phone:
                self.ids.phone_error.text = "Phone is required"
                return False
            
            cleaned_phone = re.sub(r'[\s\-]', '', phone)
            if cleaned_phone.startswith('0'):
                cleaned_phone = '+254' + cleaned_phone[1:]
            elif not cleaned_phone.startswith('+254'):
                cleaned_phone = '+254' + cleaned_phone
            
            if len(cleaned_phone) == 13:
                formatted = f"+{cleaned_phone[1:4]} {cleaned_phone[4:7]} {cleaned_phone[7:10]} {cleaned_phone[10:]}"
                self.ids.phone_input.text = formatted
            
            if not ValidationUtils.validate_kenyan_phone(phone):
                self.ids.phone_error.text = "Invalid Kenyan phone format"
                return False
            self.ids.phone_error.text = ""
            return True
        except:
            return False
    
    def validate_password(self):
        try:
            password = self.ids.password_input.text
            if not password:
                self.ids.password_error.text = "Password is required"
                return False
            is_valid, message = ValidationUtils.validate_password_strength(password)
            if not is_valid:
                self.ids.password_error.text = message
                return False
            self.ids.password_error.text = ""
            return True
        except:
            return False
    
    def on_occupation_select(self):
        try:
            occupation = self.ids.occupation_spinner.text
            if occupation == 'Student':
                self.show_institutions = True
                self.show_residence = False
                self.occupation_field_visible = True
            elif occupation == 'Alumni':
                self.show_institutions = False
                self.show_residence = True
                self.occupation_field_visible = True
            else:
                self.occupation_field_visible = False
        except Exception as e:
            print(f"Occupation selection error: {e}")
    
    def validate_occupation(self):
        try:
            occupation = self.ids.occupation_spinner.text
            if occupation not in ['Student', 'Alumni']:
                return False
            if occupation == 'Student':
                if not self.ids.institution_spinner.text or self.ids.institution_spinner.text == 'Select Institution':
                    return False
            if occupation == 'Alumni':
                if not self.ids.residence_input.text.strip():
                    return False
            return True
        except:
            return False
    
    def validate_all_fields(self):
        validations = [
            self.validate_name(),
            self.validate_email(),
            self.validate_phone(),
            self.validate_occupation(),
            self.validate_password()
        ]
        return all(validations)
    
    def collect_form_data(self):
        try:
            occupation = self.ids.occupation_spinner.text
            form_data = {
                'name': self.ids.name_input.text.strip(),
                'email': self.ids.email_input.text.strip(),
                'phone': self.ids.phone_input.text.strip(),
                'date_of_birth': self.get_selected_date(),
                'occupation': occupation,
                'password_hash': self.ids.password_input.text
            }
            if occupation == 'Student':
                form_data['institution'] = self.ids.institution_spinner.text
            elif occupation == 'Alumni':
                form_data['residence'] = self.ids.residence_input.text.strip()
            return form_data
        except Exception as e:
            print(f"Data collection error: {e}")
            return {}
    
    def submit_registration(self):
        try:
            print("Submit registration called - redirecting to OTP")
            
            if not self.validate_all_fields():
                print("Please fix validation errors")
                return
            
            form_data = self.collect_form_data()
            print(f"Form data collected: {form_data}")
            
            # AUTO-ASSIGN REGION - ADD THIS
            region = auto_assign_region(
                form_data['occupation'],
                form_data.get('institution'),
                form_data.get('residence')
            )
            form_data['region'] = region
            print(f"📍 Auto-assigned region: {region}")
            
            self.navigate_to_otp_screen(form_data)
                
        except Exception as e:
            error_msg = f"Submission error: {str(e)}"
            print(error_msg)
    
    def navigate_to_otp_screen(self, form_data):
        try:
            otp_screen = self.manager.get_screen('otp')
            otp_screen.user_email = form_data['email']
            otp_screen.pending_user_data = form_data
            otp_screen.is_password_reset = False
            otp_screen.initialized = False
            
            self.manager.current = 'otp'
            
            print(f"Navigated to OTP screen for {form_data['email']}")
        except Exception as e:
            print(f"Navigation error: {e}")
    
    def navigate_to_login(self):
        """Navigate to login screen - ADDED METHOD"""
        try:
            self.manager.current = 'login'
            print("Navigated to login screen")
        except Exception as e:
            print(f"Navigation error: {e}")
    
    def clear_form(self):
        try:
            self.ids.name_input.text = ''
            self.ids.email_input.text = ''
            self.ids.phone_input.text = ''
            self.ids.password_input.text = ''
            self.ids.residence_input.text = ''
            self.ids.name_error.text = ''
            self.ids.email_error.text = ''
            self.ids.phone_error.text = ''
            self.ids.password_error.text = ''
            
            self.ids.occupation_spinner.text = 'Student'
            self.ids.institution_spinner.text = 'University of Nairobi'
            self.on_occupation_select()
            self.on_date_change()
            
            print("Form cleared successfully")
        except Exception as e:
            print(f"Error clearing form: {e}")

class LoginScreen(Screen):
    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        self.db_manager = DatabaseManager()
    
    def validate_email(self):
        try:
            email = self.ids.email_input.text.strip()
            if not email:
                self.ids.email_error.text = "Email is required"
                return False
            if not ValidationUtils.validate_email(email):
                self.ids.email_error.text = "Invalid email format"
                return False
            self.ids.email_error.text = ""
            return True
        except:
            return False
    
    def validate_password(self):
        try:
            password = self.ids.password_input.text
            if not password:
                self.ids.password_error.text = "Password is required"
                return False
            self.ids.password_error.text = ""
            return True
        except:
            return False
    
    def login_user(self):
        try:
            if not self.validate_email() or not self.validate_password():
                return

            email = self.ids.email_input.text.strip()
            password = self.ids.password_input.text

            # Verify credentials
            success, message, user_name, region, is_admin = self.db_manager.verify_user_credentials(email, password)

            if success:
                # Fetch full user info
                user_data = self.db_manager.get_user_by_email(email)
                if not user_data:
                    self.ids.password_error.text = "User data not found."
                    self.ids.password_error.color = (1, 0, 0, 1)
                    return

                # Store in app global state
                app = App.get_running_app()
                app.current_user = user_data
                app.current_user_email = email
                app.is_admin = user_data.get('is_admin', False)

                print(f"Current user loaded: {user_data['name']} | Admin: {app.is_admin}")

                # UI feedback
                self.ids.email_error.text = ""
                self.ids.password_error.color = (0, 1, 0, 1)
                self.ids.password_error.text = "Login successful!"

                # Clear the form
                self.ids.email_input.text = ""
                self.ids.password_input.text = ""

                # Route to dashboard (for both admin and user)
                def _route(dt):
                    dashboard_screen = self.manager.get_screen('user_dashboard')
                    dashboard_screen.first_name = user_data['name'].split()[0]
                    self.manager.current = 'user_dashboard'

                from kivy.clock import Clock
                Clock.schedule_once(_route, 0.5)

            else:
                # Invalid login
                self.ids.password_error.text = message
                self.ids.password_error.color = (1, 0, 0, 1)

        except Exception as e:
            print(f"Login error: {e}")
            self.ids.password_error.text = "Login error. Please try again."
            self.ids.password_error.color = (1, 0, 0, 1)



            def navigate_to_dashboard(self, user_name):
                """Navigate to user dashboard with user's first name"""
                try:
                    dashboard_screen = self.manager.get_screen('user_dashboard')

                    # Extract first name from full name
                    if user_name:
                        first_name = user_name.split()[0]  # Get first name
                        dashboard_screen.first_name = first_name
                        print(f"Setting dashboard first name to: {first_name}")

                    self.manager.current = 'user_dashboard'
                    print("Navigated to user dashboard")

                except Exception as e:
                    print(f"Dashboard navigation error: {e}")

            def navigate_to_forgot_password(self):
                try:
                    self.manager.current = 'forgot_password'
                except Exception as e:
                    print(f"Navigation error: {e}")

            def navigate_to_registration(self):
                try:
                    self.manager.current = 'registration'
                except Exception as e:
                    print(f"Navigation error: {e}")

class ForgotPasswordScreen(Screen):
    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        self.db_manager = DatabaseManager()
    
    def validate_email(self):
        try:
            email = self.ids.email_input.text.strip()
            if not email:
                self.ids.email_error.text = "Email is required"
                return False
            if not ValidationUtils.validate_email(email):
                self.ids.email_error.text = "Invalid email format"
                return False
            
            if not self.db_manager.check_email_exists(email):
                self.ids.email_error.text = "No account found with this email"
                return False
            
            self.ids.email_error.text = ""
            return True
        except Exception as e:
            print(f"Email validation error: {e}")
            self.ids.email_error.text = "Validation error. Please try again."
            return False
    
    def send_reset_otp(self):
        try:
            if not self.validate_email():
                return
            
            email = self.ids.email_input.text.strip()
            
            otp_screen = self.manager.get_screen('otp')
            otp_screen.user_email = email
            otp_screen.pending_user_data = None
            otp_screen.is_password_reset = True
            otp_screen.initialized = False
            
            self.manager.current = 'otp'
            
            print(f"Navigated to OTP screen for password reset: {email}")
            
        except Exception as e:
            print(f"Password reset error: {e}")
            self.ids.email_error.text = "Error sending OTP. Please try again."
    
    def go_back_to_login(self):
        try:
            self.manager.current = 'login'
        except Exception as e:
            print(f"Navigation error: {e}")

class ResetPasswordScreen(Screen):
    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        self.db_manager = DatabaseManager()
        self.user_email = ""
    
    def validate_passwords(self):
        try:
            new_password = self.ids.new_password.text
            confirm_password = self.ids.confirm_password.text
            
            if not new_password:
                self.ids.reset_password_error.text = "New password is required"
                return False
            
            if not confirm_password:
                self.ids.reset_password_error.text = "Please confirm your password"
                return False
            
            if new_password != confirm_password:
                self.ids.reset_password_error.text = "Passwords do not match"
                return False
            
            is_valid, message = ValidationUtils.validate_password_strength(new_password)
            if not is_valid:
                self.ids.reset_password_error.text = message
                return False
            
            self.ids.reset_password_error.text = ""
            return True
            
        except Exception as e:
            print(f"Password validation error: {e}")
            self.ids.reset_password_error.text = "Validation error. Please try again."
            return False
    
    def reset_password(self):
        try:
            if not self.validate_passwords():
                return
            
            new_password = self.ids.new_password.text
            
            success, message = self.db_manager.update_user_password(self.user_email, new_password)
            
            if success:
                self.ids.reset_password_error.color = (0, 1, 0, 1)
                self.ids.reset_password_error.text = "Password reset successfully!"
                print(f"Password reset successful for: {self.user_email}")
                
                self.ids.new_password.text = ""
                self.ids.confirm_password.text = ""
                
                # Navigate to login after successful password reset
                Clock.schedule_once(lambda dt: self.go_back_to_login(), 2)
                
            else:
                self.ids.reset_password_error.color = (1, 0, 0, 1)
                self.ids.reset_password_error.text = message
                
        except Exception as e:
            print(f"Password reset error: {e}")
            self.ids.reset_password_error.text = "Error resetting password. Please try again."
            self.ids.reset_password_error.color = (1, 0, 0, 1)
    
    def go_back_to_login(self):
        try:
            self.manager.current = 'login'
            self.user_email = ""
            self.ids.reset_password_error.text = ""
        except Exception as e:
            print(f"Navigation error: {e}")

class OTPScreen(Screen):
    user_email = StringProperty('')
    timer_seconds = NumericProperty(600)
    otp_code = StringProperty('')
    is_password_reset = BooleanProperty(False)
    
    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        self.otp_fields = []
        self.generated_otp = ""
        self.pending_user_data = None
        self.db_manager = DatabaseManager()
        self.timer_event = None
        self.is_pasting = False
        self.can_resend = False
        self.initialized = False
        print("🔄 OTP Screen instance created")
    
    def on_enter(self):
        """Called when screen is entered"""
        print(f"🚀 OTP Screen entered - Email: {self.user_email}, Password Reset: {self.is_password_reset}")
        Clock.schedule_once(self.delayed_initialize, 0.5)
    
    def delayed_initialize(self, dt):
        """Initialize after ensuring KV is loaded"""
        try:
            print("🔄 Starting delayed initialization...")
            self.initialize_otp_fields()
            self.initialize_otp_functionality()
        except Exception as e:
            print(f"❌ Delayed initialization error: {e}")
            import traceback
            traceback.print_exc()
    
    def initialize_otp_fields(self):
        """Initialize OTP input fields with error handling"""
        try:
            print("🔧 Attempting to initialize OTP fields...")
            self.otp_fields = []
            otp_field_ids = ['otp_1', 'otp_2', 'otp_3', 'otp_4', 'otp_5', 'otp_6']
            
            for field_id in otp_field_ids:
                try:
                    if hasattr(self.ids, field_id):
                        field = getattr(self.ids, field_id)
                        self.otp_fields.append(field)
                        print(f"✅ Loaded OTP field: {field_id}")
                    else:
                        print(f"❌ Could not find OTP field: {field_id}")
                        self.otp_fields.append(None)
                except Exception as e:
                    print(f"❌ Error loading {field_id}: {e}")
                    self.otp_fields.append(None)
            
            loaded_count = len([f for f in self.otp_fields if f is not None])
            if loaded_count == 6:
                print("✅ All OTP fields initialized successfully")
                return True
            else:
                print(f"⚠️ Only {loaded_count}/6 OTP fields loaded")
                return False
                
        except Exception as e:
            print(f"❌ OTP fields initialization error: {e}")
            return False
    
    def initialize_otp_functionality(self):
        """Initialize OTP screen functionality"""
        try:
            print(f"🎯 Initializing OTP functionality for: {self.user_email}")
            
            if not self.user_email:
                print("❌ No user email provided")
                return
            
            # Set UI text
            self.update_ui_text()
            
            # Generate and send OTP
            success = self.generate_and_send_otp()
            
            if success:
                self.start_otp_timer()
                self.focus_first_field()
                self.initialized = True
                print("✅ OTP Screen initialized successfully")
            else:
                print("❌ Failed to initialize OTP functionality")
            
        except Exception as e:
            print(f"❌ OTP functionality initialization error: {e}")
    
    def update_ui_text(self):
        """Update UI text based on password reset or registration"""
        try:
            if hasattr(self.ids, 'otp_instructions'):
                if self.is_password_reset:
                    self.ids.otp_instructions.text = f'Please enter the OTP sent to {self.user_email} to reset your password'
                else:
                    self.ids.otp_instructions.text = f'Please enter the OTP sent to the email {self.user_email}'
            
            if hasattr(self.ids, 'otp_title'):
                if self.is_password_reset:
                    self.ids.otp_title.text = 'Reset Password Verification'
                else:
                    self.ids.otp_title.text = 'Verify Your Account'
        except Exception as e:
            print(f"❌ Error updating UI text: {e}")
    
    def focus_first_field(self):
        """Focus the first OTP field"""
        try:
            if self.otp_fields and self.otp_fields[0]:
                self.otp_fields[0].focus = True
        except Exception as e:
            print("⚠️ Could not focus first OTP field")
    
    def on_otp_text_change(self, index, text):
        """Handle OTP text changes and move focus automatically when digit is entered"""
        try:
            # Only move to next field when a digit is entered
            if text and len(text) == 1 and text.isdigit() and index < 5:
                next_index = index + 1
                if next_index < len(self.otp_fields) and self.otp_fields[next_index]:
                    # Small delay to ensure smooth transition
                    Clock.schedule_once(
                        lambda dt: setattr(self.otp_fields[next_index], 'focus', True), 
                        0.05
                    )
            
            # Update the complete OTP code
            self.update_otp_code()
            
        except Exception as e:
            print(f"❌ OTP text change error: {e}")
    
    def on_otp_backspace(self, index, text):
        """Handle backspace - move to previous field when current field is empty"""
        try:
            # If text is empty and we're not on the first field, move to previous field
            if not text and index > 0:
                prev_index = index - 1
                if prev_index >= 0 and self.otp_fields[prev_index]:
                    Clock.schedule_once(
                        lambda dt: setattr(self.otp_fields[prev_index], 'focus', True), 
                        0.05
                    )
        except Exception as e:
            print(f"❌ OTP backspace error: {e}")
    
    def handle_paste_operation(self, text, index):
        """Handle paste operations"""
        try:
            self.is_pasting = True
            
            # Clear all fields first
            for i in range(min(6, len(self.otp_fields))):
                if self.otp_fields[i]:
                    self.otp_fields[i].text = ''
            
            # Fill fields with pasted digits
            for i, digit in enumerate(text[:6]):
                if i < len(self.otp_fields) and self.otp_fields[i] and digit.isdigit():
                    self.otp_fields[i].text = digit
            
            # Focus the last filled field
            last_index = min(5, len(text) - 1)
            if last_index < len(self.otp_fields) and self.otp_fields[last_index]:
                Clock.schedule_once(
                    lambda dt: setattr(self.otp_fields[last_index], 'focus', True), 
                    0.05
                )
            
            self.is_pasting = False
            self.update_otp_code()
            
        except Exception as e:
            print(f"❌ Paste operation error: {e}")
            self.is_pasting = False
    
    def generate_and_send_otp(self):
        """Generate and send OTP to user's email"""
        try:
            print(f"📧 Generating OTP for: {self.user_email}")
            
            # Check rate limiting
            rate_ok, rate_message = self.db_manager.check_rate_limit(self.user_email)
            if not rate_ok:
                self.show_error_message(rate_message)
                return False
            
            # Generate OTP
            self.generated_otp = OTPUtils.generate_otp()
            print(f"🔢 OTP Generated: {self.generated_otp}")
            
            # Determine purpose
            purpose = 'password_reset' if self.is_password_reset else 'registration'
            
            # Hash and store OTP
            otp_hash = OTPUtils.hash_otp(self.generated_otp)
            storage_success = self.db_manager.store_otp(
                self.user_email, 
                otp_hash, 
                self.pending_user_data,
                purpose
            )
            
            if not storage_success:
                self.show_error_message("Error storing OTP. Please try again.")
                return False
            
            # Send OTP via email
            email_sent = OTPUtils.send_otp_email(self.user_email, self.generated_otp, self.is_password_reset)
            
            if email_sent:
                self.show_success_message("OTP sent successfully!")
                print(f"✅ OTP sent to: {self.user_email}")
                return True
            else:
                self.show_error_message("Failed to send OTP email. Please try again.")
                return False
                
        except Exception as e:
            print(f"❌ OTP generation error: {e}")
            self.show_error_message("Error generating OTP. Please try again.")
            return False
    
    def show_error_message(self, message):
        """Show error message to user"""
        try:
            if hasattr(self.ids, 'otp_error'):
                self.ids.otp_error.color = (1, 0, 0, 1)
                self.ids.otp_error.text = message
            else:
                print(f"❌ Error (no display): {message}")
        except Exception as e:
            print(f"❌ Error showing error message: {e}")
    
    def show_success_message(self, message):
        """Show success message to user"""
        try:
            if hasattr(self.ids, 'otp_error'):
                self.ids.otp_error.color = (0, 1, 0, 1)
                self.ids.otp_error.text = message
                Clock.schedule_once(lambda dt: self.clear_message(), 3)
        except Exception as e:
            print(f"❌ Error showing success message: {e}")
    
    def clear_message(self):
        """Clear the message display"""
        try:
            if hasattr(self.ids, 'otp_error'):
                self.ids.otp_error.text = ""
        except Exception as e:
            print(f"❌ Error clearing message: {e}")
    
    def start_otp_timer(self):
        """Start the OTP expiration timer"""
        try:
            self.timer_seconds = OTPConfig.OTP_EXPIRY_MINUTES * 60
            self.can_resend = False
            
            if hasattr(self.ids, 'resend_button'):
                self.ids.resend_button.disabled = True
            
            if hasattr(self.ids, 'timer_label'):
                self.ids.timer_label.text = f"OTP expires in {OTPConfig.OTP_EXPIRY_MINUTES:02d}:00"
            
            # Cancel any existing timer
            if self.timer_event:
                self.timer_event.cancel()
            
            # Start new timer
            self.timer_event = Clock.schedule_interval(self.update_timer, 1)
            print("⏰ OTP timer started")
            
        except Exception as e:
            print(f"❌ Timer start error: {e}")
    
    def update_timer(self, dt):
        """Update the OTP timer"""
        try:
            self.timer_seconds -= 1
            
            if self.timer_seconds <= 0:
                # Timer expired
                if hasattr(self.ids, 'timer_label'):
                    self.ids.timer_label.text = "OTP expired"
                if hasattr(self.ids, 'resend_button'):
                    self.ids.resend_button.disabled = False
                self.can_resend = True
                
                if self.timer_event:
                    self.timer_event.cancel()
                return False
            
            # Update timer display
            minutes = self.timer_seconds // 60
            seconds = self.timer_seconds % 60
            if hasattr(self.ids, 'timer_label'):
                self.ids.timer_label.text = f"OTP expires in {minutes:02d}:{seconds:02d}"
            
            return True
            
        except Exception as e:
            print(f"❌ Timer update error: {e}")
            return False
    
    def update_otp_code(self):
        """Update the complete OTP code from all fields"""
        try:
            if not self.otp_fields:
                return
                
            self.otp_code = ''.join([field.text for field in self.otp_fields if field and field.text])
        except Exception as e:
            print(f"❌ OTP code update error: {e}")
    
    def verify_otp(self):
        """Verify the entered OTP code"""
        try:
            if len(self.otp_code) != 6:
                self.show_error_message("Please enter all 6 digits")
                return
            
            print(f"🔍 Verifying OTP: {self.otp_code} for {self.user_email}")
            
            is_valid, message, user_data, purpose = self.db_manager.verify_otp(self.user_email, self.otp_code)
            
            if is_valid:
                self.show_success_message("OTP verified successfully!")
                print("✅ OTP verification successful")
                
                if purpose == 'password_reset':
                    self.navigate_to_new_password()
                else:
                    self.process_user_registration(user_data)
                    
            else:
                self.show_error_message(message)
                print(f"❌ OTP verification failed: {message}")
                
        except Exception as e:
            print(f"❌ OTP verification error: {e}")
            self.show_error_message("Verification error. Please try again.")
    
    def process_user_registration(self, user_data):
        """Process user registration after OTP verification"""
        try:
            if user_data:
                success, result = self.db_manager.save_user(user_data)
                
                if success:
                    user_id = result
                    print(f"✅ User data saved successfully! User ID: {user_id}")
                    self.show_success_message("Account created successfully!")
                    self.navigate_to_login()
                else:
                    self.show_error_message(f"Registration failed: {result}")
            else:
                self.show_error_message("No user data found. Please restart registration.")
                
        except Exception as e:
            print(f"❌ User registration error: {e}")
            self.show_error_message("Registration error. Please try again.")
    
    def navigate_to_new_password(self):
        """Navigate to password reset screen"""
        try:
            reset_screen = self.manager.get_screen('reset_password')
            reset_screen.user_email = self.user_email
            self.cleanup()
            self.manager.current = 'reset_password'
            print("🔄 Navigated to password reset screen")
        except Exception as e:
            print(f"❌ Navigation to password reset error: {e}")
    
    def navigate_to_login(self):
        """Navigate to login screen after successful registration"""
        try:
            registration_screen = self.manager.get_screen('registration')
            registration_screen.clear_form()
            self.cleanup()
            self.manager.current = 'login'
            print("🔄 Navigated to login screen")
        except Exception as e:
            print(f"❌ Navigation to login error: {e}")
    
    def resend_otp(self):
        """Resend OTP to user"""
        try:
            if not self.can_resend:
                return
                
            print("🔄 Resending OTP...")
            
            # Clear OTP fields
            if self.otp_fields:
                for field in self.otp_fields:
                    if field:
                        field.text = ""
            
            self.clear_message()
            
            # Generate and send new OTP
            success = self.generate_and_send_otp()
            
            if success:
                self.start_otp_timer()
                self.focus_first_field()
            else:
                if hasattr(self.ids, 'resend_button'):
                    self.ids.resend_button.disabled = True
                
        except Exception as e:
            print(f"❌ OTP resend error: {e}")
            self.show_error_message("Error resending OTP. Please try again.")
    
    def go_back_to_registration(self):
        """Navigate back to registration screen"""
        try:
            self.cleanup()
            self.manager.current = 'registration'
            print("🔄 Navigated back to registration")
        except Exception as e:
            print(f"❌ Back navigation error: {e}")
    
    def cleanup(self):
        """Clean up resources and reset state"""
        try:
            # Stop timer
            if self.timer_event:
                self.timer_event.cancel()
                self.timer_event = None
            
            # Reset state
            self.initialized = False
            self.otp_code = ""
            self.generated_otp = ""
            self.can_resend = False
            
            # Clear OTP fields
            if self.otp_fields:
                for field in self.otp_fields:
                    if field:
                        field.text = ""
            
            print("🧹 OTP screen cleaned up")
            
        except Exception as e:
            print(f"❌ Cleanup error: {e}")
    
    def on_leave(self, *args):
        """Called when leaving the screen"""
        try:
            self.cleanup()
            print("👋 OTP screen left")
        except Exception as e:
            print(f"❌ OTP screen leave error: {e}")

# UPDATE ScreenManagement TO INCLUDE CHAT SCREEN
class ScreenManagement(ScreenManager):
    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        self.add_widget(LoginScreen(name='login'))
        self.add_widget(RegistrationScreen(name='registration'))
        self.add_widget(OTPScreen(name='otp'))
        self.add_widget(ForgotPasswordScreen(name='forgot_password'))
        self.add_widget(ResetPasswordScreen(name='reset_password'))
        self.add_widget(UserDashboardScreen(name='user_dashboard'))
        self.add_widget(AboutScreen(name='about'))
        self.add_widget(ChatRouterScreen(name='chat'))
        self.add_widget(AdminChatScreen(name='admin_chat'))
        self.add_widget(UserChatScreen(name='user_chat'))
        self.add_widget(SettingsRouter(name='settings'))
        self.add_widget(AdminSettingsScreen(name='AdminSettingsScreen'))
        self.add_widget(UserSettingsScreen(name='UserSettingsScreen'))
# UPDATE KrakenApp TO INCLUDE APPWRITE BACKEND
class KrakenApp(App):
    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        self.backend = None
    
    def build(self):
        self.title = "CLC Kenya App"
        Window.size = (400, 700)
        
        # Initialize AppWrite backend
        try:
            from appwrite_backend import AppWriteBackend
            self.backend = AppWriteBackend()
            print("✅ AppWrite backend initialized")
        except Exception as e:
            print(f"❌ AppWrite backend initialization failed: {e}")
            self.backend = None
        
        return ScreenManagement()
    
    def on_start(self):
        print("App started successfully")
        if test_email_configuration():
            print("✅ Email service is ready - OTPs will be sent via Gmail")
        else:
            print("❌ WARNING: Email service is not configured properly")

if __name__ == '__main__':
    KrakenApp().run()