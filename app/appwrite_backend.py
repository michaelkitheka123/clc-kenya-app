import os
import json
import time
import asyncio
from kivy.storage.jsonstore import JsonStore

# Ensure chat directories exist
os.makedirs('chat_data', exist_ok=True)
os.makedirs('chat_data/images', exist_ok=True)
os.makedirs('chat_data/videos', exist_ok=True)
os.makedirs('chat_data/documents', exist_ok=True)
os.makedirs('chat_data/audio', exist_ok=True)

try:
    from appwrite.client import Client
    from appwrite.services.databases import Databases
    from appwrite.services.storage import Storage
    from appwrite.id import ID
    from appwrite.query import Query
    APPWRITE_AVAILABLE = True
except ImportError as e:
    print(f"⚠️ AppWrite imports failed: {e}")
    APPWRITE_AVAILABLE = False


class AppWriteBackend:
    def __init__(self):
        if not APPWRITE_AVAILABLE:
            print("❌ AppWrite not available - running in offline mode")
            self.online_mode = False
            return

        try:
            self.client = Client()
            self.client.set_endpoint('https://nyc.cloud.appwrite.io/v1')
            self.client.set_project('69022dc400325c342455')
            self.client.set_key('standard_3fdc9fb7f17d2b427c90e8c6c2e5ee34fa375e26a49fdb1be6c6b663318c4e3a14f748c6e16c510ce975d70314454137c4ebece802417e9c82d5a6eb8a94983b489cccd8bc57339f87779ae4b9649eda7c92c353b58716fa05f570370324ba61aa08f3dd43e78cb4618edb3d285c8adbdd9287d140bcc928e8879860b2922f24')

            self.databases = Databases(self.client)
            self.storage = Storage(self.client)

            self.database_id = 'clc_chat_db'
            self.messages_collection_id = 'messages'

            self.online_mode = True
            print("✅ AppWrite Backend Initialized - Online Mode")

        except Exception as e:
            print(f"❌ AppWrite initialization failed: {e}")
            self.online_mode = False

        self.local_store = JsonStore('chat_data/messages.json')
        self.media_dir = 'chat_data/media'

    # ============================================================
    # DATABASE SETUP
    # ============================================================
    async def initialize_chat_database(self):
        """Initialize database & messages collection (with status tracking)."""
        if not self.online_mode:
            print("⚠️ Offline mode - skipping database setup")
            return True

        try:
            print("🔄 Initializing AppWrite Chat Database...")

            # Check if DB exists
            try:
                dbs = self.databases.list()
                db_exists = any(db['$id'] == self.database_id for db in dbs['databases'])
            except Exception:
                db_exists = False

            if not db_exists:
                self.databases.create(database_id=self.database_id, name='CLC Kenya Chat')

            # Check if messages collection exists
            try:
                self.databases.get_collection(self.database_id, self.messages_collection_id)
                print("✅ Messages collection exists")
                return True
            except Exception:
                print("📝 Creating messages collection...")
                self.databases.create_collection(
                    database_id=self.database_id,
                    collection_id=self.messages_collection_id,
                    name='Chat Messages',
                    permissions=['read("any")', 'write("users")']
                )
                await asyncio.sleep(2)

                attributes = [
                    {'key': 'content', 'type': 'string', 'size': 2000, 'required': False},
                    {'key': 'sender_id', 'type': 'string', 'size': 100, 'required': True},
                    {'key': 'sender_name', 'type': 'string', 'size': 100, 'required': True},
                    {'key': 'target_groups', 'type': 'string', 'size': 500, 'required': True},
                    {'key': 'timestamp', 'type': 'integer', 'required': True},
                    {'key': 'status', 'type': 'string', 'size': 20, 'required': False},
                    {'key': 'read_by', 'type': 'string', 'size': 1000, 'required': False},
                ]

                for attr in attributes:
                    try:
                        if attr['type'] == 'string':
                            self.databases.create_string_attribute(
                                database_id=self.database_id,
                                collection_id=self.messages_collection_id,
                                key=attr['key'],
                                size=attr['size'],
                                required=attr['required']
                            )
                        elif attr['type'] == 'integer':
                            self.databases.create_integer_attribute(
                                database_id=self.database_id,
                                collection_id=self.messages_collection_id,
                                key=attr['key'],
                                required=attr['required']
                            )
                        await asyncio.sleep(0.8)
                        print(f"✅ Attribute added: {attr['key']}")
                    except Exception as e:
                        print(f"⚠️ Attribute creation failed for {attr['key']}: {e}")

                return True

        except Exception as e:
            print(f"❌ Database initialization failed: {e}")
            return False

    # ============================================================
    # MESSAGE HANDLING
    # ============================================================
    async def send_message(
        self,
        content,
        sender_id,
        sender_name,
        target_groups,
        message_type="text",        # new required field for schema
        media_path=None,
        media_type=None,
        linked_to=None              # optional link to another message
    ):
        """Send a message (text or media) and track status."""

        # Create local message object for immediate UI display
        local_message = {
            'content': content or "",
            'sender_id': sender_id,
            'sender_name': sender_name,
            'target_groups': json.dumps(target_groups),
            'timestamp': int(time.time() * 1000),
            'message_type': message_type,     # ✅ required field for AppWrite schema
            'media_path': media_path,
            'media_type': media_type,
            'linked_to': linked_to,
            'status': 'sent',
            'read_by': [],
            'local_id': f"local_{int(time.time() * 1000)}"
        }

        # Cache locally for instant UI feedback
        self._cache_message_locally(local_message)

        if not self.online_mode:
            print("✅ Message cached locally (offline mode)")
            return local_message

        try:
            # Prepare data for AppWrite API
            message_data = dict(local_message)
            message_data.pop('local_id', None)

            # Remove None values (AppWrite rejects null attributes)
            message_data = {k: v for k, v in message_data.items() if v is not None}

            # Send message to AppWrite
            result = self.databases.create_document(
                database_id=self.database_id,
                collection_id=self.messages_collection_id,
                document_id=ID.unique(),
                data=message_data
            )

            print(f"✅ Message sent to AppWrite: {result['$id']}")
            return result

        except Exception as e:
            print(f"❌ Error sending message: {e}")
            return None

    async def get_messages(self, user_groups=None):
        """Fetch messages with status and read tracking."""
        if user_groups is None:
            user_groups = ['all_users']

        if self.online_mode:
            try:
                result = self.databases.list_documents(
                    database_id=self.database_id,
                    collection_id=self.messages_collection_id,
                    queries=[
                        Query.order_desc("timestamp"),
                        Query.contains("target_groups", user_groups)
                    ]
                )
                filtered = []
                for msg in result['documents']:
                    try:
                        groups = json.loads(msg.get('target_groups', '[]'))
                        if any(g in groups for g in user_groups):
                            filtered.append(msg)
                    except:
                        filtered.append(msg)
                print(f"📨 Retrieved {len(filtered)} messages from AppWrite")
                return filtered
            except Exception as e:
                print(f"❌ Error fetching from AppWrite: {e}")

        return self.get_local_messages()

    def get_local_messages(self):
        try:
            if 'messages' in self.local_store:
                msgs = self.local_store.get('messages')
                lst = list(msgs.values())
                lst.sort(key=lambda x: x.get('timestamp', 0))
                return lst
            return []
        except Exception as e:
            print(f"❌ Local message retrieval error: {e}")
            return []

    def _cache_message_locally(self, data):
        try:
            all_msgs = self.local_store.get('messages') if 'messages' in self.local_store else {}
            msg_id = data.get('local_id', f"local_{int(time.time()*1000)}")
            all_msgs[msg_id] = data
            self.local_store.put('messages', **all_msgs)
            print(f"💾 Cached locally: {msg_id}")
        except Exception as e:
            print(f"❌ Local cache error: {e}")

    # ============================================================
    # STATUS UPDATES
    # ============================================================
    def update_message_status(self, message_id, new_status):
        """Update sent → delivered → read status."""
        if not self.online_mode:
            return False
        try:
            self.databases.update_document(
                database_id=self.database_id,
                collection_id=self.messages_collection_id,
                document_id=message_id,
                data={'status': new_status}
            )
            print(f"✅ Updated message {message_id} to {new_status}")
            return True
        except Exception as e:
            print(f"❌ update_message_status error: {e}")
            return False


    def mark_message_as_read(self, message_id, user_id):
        """Marks a message as read by a specific user."""
        try:
            # Fetch message document (synchronous)
            msg = self.databases.get_document(
                database_id=self.database_id,
                collection_id=self.messages_collection_id,
                document_id=message_id
            )

            read_by = msg.get("read_by", [])

            # ✅ Normalize read_by into a list
            if isinstance(read_by, str):
                try:
                    read_by = json.loads(read_by)
                except Exception:
                    read_by = []
            elif not isinstance(read_by, list):
                read_by = []

            # Add user if not already there
            if user_id not in read_by:
                read_by.append(user_id)

            # ✅ Appwrite expects an array, not JSON string
            result = self.databases.update_document(
                database_id=self.database_id,
                collection_id=self.messages_collection_id,
                document_id=message_id,
                data={"read_by": read_by, "status": "read"}
            )

            print(f"✅ Marked message {message_id} as read by {user_id}")
            return True

        except Exception as e:
            print(f"❌ mark_message_as_read error: {e}")
            return False
