
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

# Get the absolute path to the font file
current_dir = os.path.dirname(os.path.abspath(__file__))
font_path = os.path.join(current_dir, 'fonts', 'otfs', 'Font Awesome 7 Free-Solid-900.otf')
LabelBase.register(name='fa-solid-900.ttf', fn_regular=font_path)  # ADD THIS LINE
print("Font registered successfully with both names!")
print(f"Looking for font at: {font_path}")  # Debug print

# Check if file exists
if os.path.exists(font_path):
    LabelBase.register(name='FontAwesomeSolid', fn_regular=font_path)
    print("Font registered successfully!")
else:
    print(f"Font file not found at: {font_path}")
    # List what's actually in the directory
    fonts_dir = os.path.join(current_dir, 'fonts', 'otfs')
    if os.path.exists(fonts_dir):
        print("Files in fonts/otfs:", os.listdir(fonts_dir))

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
    
    # NEW METHODS FOR CHAT FUNCTIONALITY
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
                SELECT id, name, email, region, is_admin FROM users
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
    first_name = StringProperty("User")  # Will be set dynamically
    
    def __init__(self, **kwargs):
        super().__init__(**kwargs)
    
    def on_pre_enter(self):
        """Called when the screen is about to be shown"""
        print(f"Dashboard loaded for user: {self.first_name}")
    
    def navigate_to_about(self):
        try:
            self.manager.current = 'about'
            print("Navigated to About screen")
        except Exception as e:
            print(f"Navigation error: {e}")
    
    def navigate_to_chats(self):
        try:
            self.manager.current = 'chat'
            print("Navigated to Chat screen")
        except Exception as e:
            print(f"Chat navigation error: {e}")
    
    def navigate_to_notifications(self):
        print("Navigate to Notifications")
        # Implementation for Notifications navigation
    
    def navigate_to_settings(self):
        try:
            self.manager.current = 'settings'
            print("Navigated to Settings screen")
        except Exception as e:
            print(f"Settings navigation error: {e}")
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


class AdminChatScreen(Screen):
    """Admin-only chat interface for sending messages to user groups."""
    
    backend = None
    current_user = None
    user_email = None
    available_groups = []
    current_chat_group = "all_users"
    pinned_messages = []
    message_poll_event = None

    # =====================================================
    # SCREEN ENTRY / INITIALIZATION
    # =====================================================
    def on_enter(self):
        """Initialize backend connection and load initial messages."""
        try:
            app = App.get_running_app()
            self.backend = app.backend
            self.current_user = "admin001"   # TODO: Replace with actual session user
            self.user_email = "admin@clckenya.org"
            self.available_groups = [
                "all_users", "nairobi", "rift_valley", "coastal", "western", "central"
            ]

            print("🧑‍💼 AdminChatScreen initialized")

            # Load messages immediately and start polling
            self.load_messages()
            self.start_message_polling()

        except Exception as e:
            print(f"❌ on_enter error: {e}")

    def on_leave(self):
        """Stop background polling when leaving the screen."""
        try:
            if self.message_poll_event:
                self.message_poll_event.cancel()
        except Exception as e:
            print(f"on_leave cleanup error: {e}")

    # =====================================================
    # MESSAGE SENDING
    # =====================================================
    def send_message(self):
        """Triggered by the Send button."""
        try:
            content = self.ids.message_input.text.strip()
            if not content:
                return

            # Display immediately in UI (temporary message)
            temp = {
                "id": f"local_{int(time.time() * 1000)}",
                "sender_id": self.current_user,
                "sender_name": "Admin",
                "content": content,
                "timestamp": datetime.now().strftime("%H:%M"),
                "status": "sending",
                "message_type": "text",
                "media_path": None,
                "media_name": None
            }
            self.add_message_card(temp)
            self.scroll_to_bottom()

            # Clear input field
            self.ids.message_input.text = ""

            # Send asynchronously
            threading.Thread(target=self._send_async, args=(content,), daemon=True).start()

        except Exception as e:
            print(f"❌ send_message error: {e}")

    def _send_async(self, content):
        """Send message to backend asynchronously."""
        try:
            async def do_send():
                result = await self.backend.send_message(
                    content=content,
                    sender_id=self.current_user,
                    sender_name="Admin",
                    target_groups=[self.current_chat_group]
                )
                if result:
                    print("✅ Sent to AppWrite")
                    Clock.schedule_once(lambda dt: self.load_messages(), 1)

            loop = asyncio.new_event_loop()
            asyncio.set_event_loop(loop)
            loop.run_until_complete(do_send())
            loop.close()

        except Exception as e:
            print(f"❌ send async failed: {e}")

    # =====================================================
    # MESSAGE FETCHING / RENDERING
    # =====================================================
    def start_message_polling(self):
        """Periodically refresh chat messages (every 10s)."""
        try:
            if self.message_poll_event:
                self.message_poll_event.cancel()
            self.message_poll_event = Clock.schedule_interval(lambda dt: self.load_messages(), 10)
            print("🔄 Started message polling")
        except Exception as e:
            print(f"Polling start error: {e}")

    def load_messages(self):
        """Load messages from backend asynchronously."""
        try:
            def background_fetch():
                try:
                    async def get_msgs():
                        msgs = await self.backend.get_messages([self.current_chat_group])
                        if msgs:
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
        """Render all messages inside the scroll container."""
        try:
            container = self.ids.message_container
            container.clear_widgets()

            # Sort oldest → newest
            for msg in sorted(messages, key=lambda m: m.get("timestamp", 0)):
                msg_dict = {
                    "id": msg.get("$id", ""),
                    "sender_id": msg.get("sender_id", ""),
                    "sender_name": msg.get("sender_name", ""),
                    "content": msg.get("content", ""),
                    "timestamp": datetime.fromtimestamp(
                        msg.get("timestamp", time.time())
                    ).strftime("%H:%M"),
                    "status": "delivered",
                    "message_type": msg.get("media_type", "text"),
                    "media_path": msg.get("media_path"),
                    "media_name": os.path.basename(msg.get("media_path")) if msg.get("media_path") else None
                }
                self.add_message_card(msg_dict)
            self.scroll_to_bottom()
        except Exception as e:
            print(f"render_messages error: {e}")

    # =====================================================
    # MESSAGE CARD CREATION
    # =====================================================
    def open_emoji_picker(self):
        """Placeholder for emoji picker."""
        print("😀 Emoji picker clicked — placeholder")

    def add_message_card(self, msg):
        """Create instance of AdminMessageCard (defined in KV)."""
        try:
            widget_name = "AdminMessageCard"
            widget_cls = getattr(Factory, widget_name, None)
            if not widget_cls:
                print(f"❌ add_message_card error: Unknown <{widget_name}> in KV")
                return

            # Adjust content mapping
            if widget_name == "AdminMessageCard" and "content" in msg:
                msg["content_text"] = msg.pop("content")

            # Instantiate widget and assign properties
            card = widget_cls()
            mapping = {
                "id": "message_id",
                "message_id": "message_id",
                "sender_name": "sender_name",
                "content_text": "content_text",
                "timestamp": "timestamp",
                "message_type": "message_type",
                "media_path": "media_path",
                "media_name": "media_name",
                "status": "status"
            }

            for k, v in msg.items():
                prop = mapping.get(k, k)
                try:
                    setattr(card, prop, v)
                except Exception:
                    pass

            # Add to UI
            self.ids.message_container.add_widget(card)
        except Exception as e:
            print(f"❌ add_message_card error: {e}")

    def scroll_to_bottom(self):
        """Scroll chat view to the latest message."""
        try:
            self.ids.scroll_view.scroll_y = 0
        except Exception:
            pass

    # =====================================================
    # ATTACHMENTS
    # =====================================================
    def open_attachment_picker(self):
        """Open file chooser to attach images, videos, or documents."""
        try:
            fc = FileChooserListView(filters=["*.jpg", "*.png", "*.mp4", "*.pdf", "*.docx"])
            popup = Popup(title="📎 Select a file", content=fc, size_hint=(0.9, 0.8))
            fc.bind(on_submit=lambda fc, sel, touch: self._send_attachment(popup, sel))
            popup.open()
        except Exception as e:
            print(f"attachment_picker error: {e}")

    def _send_attachment(self, popup, selection):
        popup.dismiss()
        if not selection:
            return
        file_path = selection[0]
        ext = os.path.splitext(file_path)[1].lower()
        media_type = (
            "image" if ext in [".jpg", ".jpeg", ".png"]
            else "video" if ext in [".mp4", ".mov"]
            else "document"
        )

        temp = {
            "id": f"local_{int(time.time() * 1000)}",
            "sender_id": self.current_user,
            "sender_name": "Admin",
            "content": "",
            "timestamp": datetime.now().strftime("%H:%M"),
            "status": "sending",
            "message_type": media_type,
            "media_path": file_path,
            "media_name": os.path.basename(file_path)
        }
        self.add_message_card(temp)
        threading.Thread(
            target=self._upload_media_async, args=(file_path, media_type), daemon=True
        ).start()

    def _upload_media_async(self, file_path, media_type):
        """Upload attachment asynchronously."""
        try:
            async def do_upload():
                result = await self.backend.send_message(
                    content="",
                    sender_id=self.current_user,
                    sender_name="Admin",
                    target_groups=[self.current_chat_group],
                    media_path=file_path,
                    media_type=media_type
                )
                if result:
                    Clock.schedule_once(lambda dt: self.load_messages(), 1)

            loop = asyncio.new_event_loop()
            asyncio.set_event_loop(loop)
            loop.run_until_complete(do_upload())
            loop.close()
        except Exception as e:
            print(f"upload_media error: {e}")

    # =====================================================
    # PINNING / DELETING
    # =====================================================
    def pin_message(self, message_id):
        """Pin a message locally."""
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
                self.backend.databases.delete_document(
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

    # =====================================================
    # STATS OVERLAY
    # =====================================================
    def toggle_stats(self, message_id):
        """Show or hide stats overlay for message card."""
        try:
            card = self.ids.message_container.ids.get(message_id)
            if not card:
                print("No card found for stats toggle")
                return
            if hasattr(card, "stats_visible"):
                card.stats_visible = not card.stats_visible
        except Exception as e:
            print(f"toggle_stats error: {e}")

    # =====================================================
    # RECIPIENT SELECTION
    # =====================================================
    def open_recipient_selector(self):
        """Bottom sheet for selecting recipient group."""
        try:
            modal = ModalView(size_hint=(1, None), height=dp(300), background_color=(0, 0, 0, 0.7))
            layout = BoxLayout(orientation="vertical", padding=dp(12), spacing=dp(8))
            title = Label(
                text="Select Recipients", font_size=sp(18),
                color=(1, 1, 1, 1), size_hint_y=None, height=dp(40)
            )
            layout.add_widget(title)

            for group in self.available_groups:
                btn = Button(
                    text=group.upper(),
                    size_hint_y=None, height=dp(45),
                    background_color=(0.15, 0.15, 0.15, 1),
                    color=(1, 1, 1, 1),
                    on_release=lambda btn, g=group: self._select_recipient(g, modal)
                )
                layout.add_widget(btn)

            cancel = Button(
                text="Cancel", size_hint_y=None, height=dp(45),
                background_color=(0.2, 0.2, 0.2, 1),
                color=(1, 1, 1, 1),
                on_release=modal.dismiss
            )
            layout.add_widget(cancel)
            modal.add_widget(layout)
            modal.open()
        except Exception as e:
            print(f"open_recipient_selector error: {e}")

    def _select_recipient(self, group, modal):
        """Set target group for outgoing messages."""
        modal.dismiss()
        self.current_chat_group = group
        print(f"👥 Selected recipient group: {group}")


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
    pinned_messages = []
    periodic_update_event = None

    def on_enter(self):
        """When the screen loads"""
        try:
            app = App.get_running_app()
            self.backend = app.backend
            self.user_email = getattr(app, "user_email", "user@clckenya.org")
            self.current_user = getattr(app, "user_id", "user_001")
            self.user_region = getattr(app, "user_region", "nairobi")

            print(f"👤 Entered UserChatScreen for {self.user_email} ({self.user_region})")

            # Load messages and pinned items
            self.load_messages()
            self.load_pinned_messages()
            self.start_polling()
        except Exception as e:
            print(f"❌ UserChatScreen on_enter error: {e}")

    def on_leave(self):
        """Stop periodic updates"""
        try:
            if self.periodic_update_event:
                self.periodic_update_event.cancel()
                self.periodic_update_event = None
        except Exception as e:
            print(f"❌ UserChatScreen on_leave error: {e}")

    # ======================================================
    # 📥 MESSAGE FETCHING AND RENDERING
    # ======================================================

    def load_messages(self):
        """Fetch messages from AppWrite (async in thread)"""
        try:
            def background_fetch():
                try:
                    async def get_msgs():
                        msgs = await self.backend.get_messages(["all_users", self.user_region])
                        if msgs:
                            # Filter only admin messages
                            admin_msgs = [
                                m for m in msgs
                                if "admin" in m.get("sender_id", "").lower()
                                or "admin" in m.get("sender_name", "").lower()
                            ]
                            Clock.schedule_once(lambda dt: self.render_messages(admin_msgs), 0)
                        else:
                            print("⚠️ No messages found from backend")

                    loop = asyncio.new_event_loop()
                    asyncio.set_event_loop(loop)
                    loop.run_until_complete(get_msgs())
                    loop.close()
                except Exception as e:
                    print(f"❌ Error fetching messages: {e}")

            threading.Thread(target=background_fetch, daemon=True).start()
        except Exception as e:
            print(f"❌ load_messages error: {e}")

    def render_messages(self, messages):
        """Render messages to UI"""
        try:
            container = self.ids.message_container
            container.clear_widgets()

            # Sort oldest → newest
            messages_sorted = sorted(messages, key=lambda m: m.get("timestamp", 0))

            for msg in messages_sorted:
                ts = msg.get("timestamp", time.time())
                if isinstance(ts, (int, float)):
                    ts_str = datetime.fromtimestamp(ts).strftime("%H:%M")
                else:
                    try:
                        ts_str = datetime.fromisoformat(ts).strftime("%H:%M")
                    except Exception:
                        ts_str = "00:00"

                # Build message dict for KV
                msg_dict = {
                    "message_id": msg.get("$id", f"msg_{int(time.time()*1000)}"),
                    "sender_name": msg.get("sender_name", "Admin"),
                    "content": msg.get("content", ""),
                    "timestamp": ts_str,
                    "message_type": msg.get("media_type", "text"),
                    "media_path": msg.get("media_path", None),
                    "media_name": os.path.basename(msg.get("media_path")) if msg.get("media_path") else None
                }

                self.add_message_card(msg_dict)

            self.scroll_to_bottom()
            print(f"📨 Rendered {len(messages)} admin messages.")
        except Exception as e:
            print(f"❌ render_messages error: {e}")

    def add_message_card(self, msg):
        """Adds one UserMessageCard (defined in KV)"""
        try:
            card = Builder.template("UserMessageCard", **msg)
            self.ids.message_container.add_widget(card)
        except Exception as e:
            print(f"❌ add_message_card error: {e}")

    def scroll_to_bottom(self):
        """Auto-scroll to bottom after rendering"""
        try:
            self.ids.scroll_view.scroll_y = 0
        except Exception:
            pass

    # ======================================================
    # 📌 PINNED MESSAGES
    # ======================================================

    def load_pinned_messages(self):
        """Show pinned messages (local example or backend logic)"""
        try:
            self.pinned_messages = [
                {"id": "p1", "title": "📢 Welcome to CLC Kenya"},
                {"id": "p2", "title": "⚠️ Important Announcements"},
            ]
            pinned_strip = self.ids.pinned_strip
            pinned_strip.clear_widgets()

            from kivy.uix.boxlayout import BoxLayout
            from kivy.uix.label import Label
            from kivy.uix.behaviors import ButtonBehavior
            from kivy.graphics import Color, RoundedRectangle

            class PinnedCard(ButtonBehavior, BoxLayout):
                def __init__(self, title, **kwargs):
                    super().__init__(**kwargs)
                    self.orientation = "horizontal"
                    self.size_hint_x = None
                    self.width = dp(180)
                    self.padding = dp(6)
                    self.spacing = dp(4)
                    with self.canvas.before:
                        Color(0.15, 0.15, 0.15, 1)
                        self.bg = RoundedRectangle(pos=self.pos, size=self.size, radius=[dp(8)])
                    self.bind(pos=self._update_bg, size=self._update_bg)

                    lbl = Label(text=title, color=(0.95, 0.9, 0.3, 1), font_size=sp(13))
                    self.add_widget(lbl)

                def _update_bg(self, *args):
                    self.bg.pos = self.pos
                    self.bg.size = self.size

                def on_press(self):
                    print(f"📌 Tapped pinned message: {self.children[0].text}")

            for msg in self.pinned_messages:
                pinned_strip.add_widget(PinnedCard(msg["title"]))
        except Exception as e:
            print(f"❌ load_pinned_messages error: {e}")

    # ======================================================
    # 🔄 PERIODIC UPDATES
    # ======================================================

    def start_polling(self):
        """Automatically refresh messages"""
        try:
            if self.periodic_update_event:
                self.periodic_update_event.cancel()

            def refresh(dt):
                self.load_messages()

            self.periodic_update_event = Clock.schedule_interval(refresh, 10)
            print("🔁 Started user chat polling every 10s.")
        except Exception as e:
            print(f"❌ start_polling error: {e}")


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


class AdminSettingsScreen(Screen):
    """Admin Settings screen: manage users and logout."""

    users = ListProperty([])

    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        self.db_manager = DatabaseManager()
        self.current_user = None

    def on_enter(self):
        """Load all users for admin management."""
        try:
            self.current_user = self.db_manager.get_current_user()
            self.load_all_users()
        except Exception as e:
            print(f"AdminSettingsScreen init error: {e}")

    def load_all_users(self):
        """Fetch all users and display them in the list."""
        try:
            users = self.db_manager.get_all_users()
            self.ids.users_list.clear_widgets()

            for user in users:
                self.add_user_to_list(user)

            print(f"✅ Loaded {len(users)} users for admin panel")

        except Exception as e:
            print(f"Error loading users: {e}")

    def add_user_to_list(self, user):
        """Add user widget to list with promote/demote button."""
        layout = BoxLayout(
            orientation="horizontal",
            size_hint_y=None,
            height=dp(50),
            spacing=dp(10),
            padding=dp(5)
        )

        info = Label(
            text=f"{user['name']} ({user['email']})",
            size_hint_x=0.6,
            halign="left",
            valign="middle",
            text_size=(dp(180), None)
        )

        status = Label(
            text="👑 Admin" if user["is_admin"] else "👤 User",
            size_hint_x=0.2,
            color=(0.9, 0.8, 0.1, 1) if user["is_admin"] else (0.8, 0.8, 0.8, 1),
            font_size=sp(11)
        )

        # Button logic
        if user["id"] != self.current_user["id"]:
            btn = Button(
                text="Demote" if user["is_admin"] else "Promote",
                size_hint_x=0.2,
                background_color=(0.2, 0.7, 0.3, 1) if not user["is_admin"] else (0.9, 0.2, 0.2, 1),
                on_press=lambda _, u=user: self.toggle_user_role(u)
            )
        else:
            btn = Widget(size_hint_x=0.2)

        layout.add_widget(info)
        layout.add_widget(status)
        layout.add_widget(btn)
        self.ids.users_list.add_widget(layout)

    def toggle_user_role(self, user):
        """Promote or demote a user (admin only)."""
        try:
            if user["is_admin"]:
                print(f"🔽 Demoting {user['name']}...")
                success = self.db_manager.demote_admin(user["id"])
            else:
                print(f"⬆ Promoting {user['name']}...")
                success = self.db_manager.promote_to_admin(user["id"])

            if success:
                print("✅ Role updated successfully")
                Clock.schedule_once(lambda dt: self.load_all_users(), 1)
            else:
                print("❌ Role update failed")

        except Exception as e:
            print(f"Error updating role: {e}")

    def logout(self):
        """Logout and return to login screen."""
        try:
            print("🚪 Admin logging out...")
            self.db_manager.logout_current_user()
            self.manager.current = "login"
        except Exception as e:
            print(f"Logout error: {e}")


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

            self.ids.user_info.text = (
                f"👤 {user['name']}\n📧 {user['email']}\n"
                f"Role: User"
            )
        except Exception as e:
            print(f"User settings error: {e}")

    def logout(self):
        """Logout and go to login."""
        try:
            print("🚪 User logging out...")
            DatabaseManager().logout_current_user()
            self.manager.current = "login"
        except Exception as e:
            print(f"Logout error: {e}")

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

            success, message, user_name, region, is_admin = self.db_manager.verify_user_credentials(email, password)

            if success:
                # store in app global state so other screens can read it
                app = App.get_running_app()
                app.user_email = email
                app.user_name = user_name
                app.user_region = region or "nairobi"
                app.is_admin = bool(is_admin)

                # UI feedback
                self.ids.email_error.text = ""
                self.ids.password_error.text = ""
                self.ids.password_error.color = (0, 1, 0, 1)
                self.ids.password_error.text = "Login successful!"
                print(f"Login successful for: {email}")

                # Clear the form
                self.ids.email_input.text = ""
                self.ids.password_input.text = ""

                # Route: if admin go to admin chat, else normal dashboard/user chat
                # small delay to let UI show success text
                def _route(dt):
                    if app.is_admin:
                        # ensure your screen names exist
                        self.manager.current = 'admin_chat'
                    else:
                        # set dashboard name and navigate (optional)
                        try:
                            dashboard_screen = self.manager.get_screen('user_dashboard')
                            if user_name:
                                dashboard_screen.first_name = user_name.split()[0]
                        except Exception:
                            pass
                        self.manager.current = 'user_dashboard'

                from kivy.clock import Clock
                Clock.schedule_once(_route, 0.5)

            else:
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