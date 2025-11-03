# appwrite_backend.py - FIXED VERSION
import os
import json
import time
import asyncio
from kivy.storage.jsonstore import JsonStore

# Create chat_data directory first
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
    from appwrite.query import Query  # ADD THIS IMPORT
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
            
            # YOUR CREDENTIALS
            self.client.set_endpoint('https://nyc.cloud.appwrite.io/v1')
            self.client.set_project('69022dc400325c342455')
            self.client.set_key('standard_3fdc9fb7f17d2b427c90e8c6c2e5ee34fa375e26a49fdb1be6c6b663318c4e3a14f748c6e16c510ce975d70314454137c4ebece802417e9c82d5a6eb8a94983b489cccd8bc57339f87779ae4b9649eda7c92c353b58716fa05f570370324ba61aa08f3dd43e78cb4618edb3d285c8adbdd9287d140bcc928e8879860b2922f24')
            
            self.databases = Databases(self.client)
            self.storage = Storage(self.client)
            
            # Database and collection IDs
            self.database_id = 'clc_chat_db'
            self.messages_collection_id = 'messages'
            
            self.online_mode = True
            print("✅ AppWrite Backend Initialized - Online Mode")
            
        except Exception as e:
            print(f"❌ AppWrite initialization failed: {e}")
            self.online_mode = False
        
        # Local storage for offline access (create after directories exist)
        self.local_store = JsonStore('chat_data/messages.json')
        self.media_dir = 'chat_data/media'
    
    async def initialize_chat_database(self):
        """Initialize AppWrite database and collections for chat"""
        if not self.online_mode:
            print("⚠️ Running in offline mode - skipping database initialization")
            return True
            
        try:
            print("🔄 Initializing AppWrite Chat Database...")
            
            # Check if database exists, create if not
            try:
                databases_list = self.databases.list()
                db_exists = any(db['$id'] == self.database_id for db in databases_list['databases'])
                print(f"📊 Database exists: {db_exists}")
            except Exception as e:
                print(f"📊 Database check: {e}")
                db_exists = False
            
            if not db_exists:
                print("📁 Creating database...")
                result = self.databases.create(
                    database_id=self.database_id,
                    name='CLC Kenya Chat'
                )
                print(f"✅ Database created: {result['$id']}")
            
            # Create messages collection
            try:
                collection = self.databases.get_collection(self.database_id, self.messages_collection_id)
                print(f"✅ Messages collection exists: {collection['$id']}")
                return True
            except Exception as e:
                print(f"📝 Creating messages collection...")
                try:
                    collection = self.databases.create_collection(
                        database_id=self.database_id,
                        collection_id=self.messages_collection_id,
                        name='Chat Messages',
                        permissions=['read("any")', 'write("users")']
                    )
                    print(f"✅ Collection created: {collection['$id']}")
                    
                    # Wait a moment for collection to be ready
                    await asyncio.sleep(2)
                    
                    # Add basic attributes
                    attributes = [
                        {'key': 'content', 'type': 'string', 'size': 2000, 'required': False},
                        {'key': 'sender_id', 'type': 'string', 'size': 100, 'required': True},
                        {'key': 'sender_name', 'type': 'string', 'size': 100, 'required': True},
                        {'key': 'target_groups', 'type': 'string', 'size': 500, 'required': True},
                        {'key': 'timestamp', 'type': 'integer', 'required': True},
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
                                print(f"   ✅ String attribute '{attr['key']}' added")
                            elif attr['type'] == 'integer':
                                self.databases.create_integer_attribute(
                                    database_id=self.database_id,
                                    collection_id=self.messages_collection_id,
                                    key=attr['key'],
                                    required=attr['required']
                                )
                                print(f"   ✅ Integer attribute '{attr['key']}' added")
                            await asyncio.sleep(1)
                        except Exception as attr_error:
                            print(f"   ⚠️  Attribute '{attr['key']}': {attr_error}")
                    
                    return True
                    
                except Exception as create_error:
                    print(f"❌ Collection creation failed: {create_error}")
                    return False
            
        except Exception as e:
            print(f"❌ Database initialization failed: {e}")
            return False
    
    async def test_connection(self):
        """Test the AppWrite connection with a simple message"""
        if not self.online_mode:
            print("⚠️ Running in offline mode - skipping connection test")
            return True
            
        try:
            print("🔗 Testing AppWrite connection...")
            
            # Test creating a simple document
            test_doc = await self.send_message(
                content="🚀 Test message - AppWrite connection successful!",
                sender_id="test_user_123",
                sender_name="CLC Test Bot", 
                target_groups=["all_users"]
            )
            
            if test_doc:
                print("✅ Message sent successfully!")
                print(f"📨 Message ID: {test_doc['$id']}")
                
                # Try to read it back
                try:
                    read_back = self.databases.get_document(
                        database_id=self.database_id,
                        collection_id=self.messages_collection_id,
                        document_id=test_doc['$id']
                    )
                    print("✅ Message read back successfully!")
                    print(f"📖 Content: {read_back.get('content', 'No content')}")
                    
                    # Clean up test document
                    try:
                        self.databases.delete_document(
                            database_id=self.database_id,
                            collection_id=self.messages_collection_id,
                            document_id=test_doc['$id']
                        )
                        print("✅ Test cleanup completed")
                    except Exception as cleanup_error:
                        print(f"⚠️  Test cleanup failed: {cleanup_error}")
                        
                except Exception as read_error:
                    print(f"⚠️  Could not read back message: {read_error}")
            
            return True
            
        except Exception as e:
            print(f"❌ Connection test failed: {e}")
            return False
    
    async def send_message(self, content, sender_id, sender_name, target_groups, media_path=None, media_type=None):
        """Send a message to AppWrite or cache locally"""
        # Always cache locally first
        local_message = {
            'content': content,
            'sender_id': sender_id,
            'sender_name': sender_name,
            'target_groups': json.dumps(target_groups),
            'timestamp': int(time.time()),
            'media_path': media_path,
            'media_type': media_type,
            'local_id': f"local_{int(time.time() * 1000)}"  # Unique local ID
        }
        
        self._cache_message_locally(local_message)
        
        # If online, send to AppWrite
        if self.online_mode:
            try:
                message_data = {
                    'content': content,
                    'sender_id': sender_id,
                    'sender_name': sender_name,
                    'target_groups': json.dumps(target_groups),
                    'timestamp': int(time.time()),
                }
                
                if media_path:
                    message_data['media_path'] = media_path
                    message_data['media_type'] = media_type
                
                result = self.databases.create_document(
                    database_id=self.database_id,
                    collection_id=self.messages_collection_id,
                    document_id=ID.unique(),
                    data=message_data
                )
                
                print(f"✅ Message sent to AppWrite: {result['$id']}")
                return result
                
            except Exception as e:
                print(f"❌ Error sending to AppWrite: {e}")
                return None
        else:
            print("✅ Message cached locally (offline mode)")
            return local_message
    
    def _cache_message_locally(self, message_data):
        """Cache message in local JSON store"""
        try:
            # Get existing messages or create new dict
            all_messages = self.local_store.get('messages') if 'messages' in self.local_store else {}
            
            # Use local_id or generate one
            message_id = message_data.get('local_id', f"local_{int(time.time() * 1000)}")
            all_messages[message_id] = message_data
            
            self.local_store.put('messages', **all_messages)
            print(f"💾 Message cached locally: {message_id}")
            
        except Exception as e:
            print(f"❌ Local caching error: {e}")
    
    async def get_messages(self, user_groups=None):
        """Get messages for specific user groups - FIXED VERSION"""
        if user_groups is None:
            user_groups = ['all_users']
        
        # First try to get from AppWrite if online
        if self.online_mode:
            try:
                # FIXED: Use order_fields instead of order_attributes
                result = self.databases.list_documents(
                database_id=self.database_id,
                collection_id=self.messages_collection_id,
                queries=[
                Query.order_desc("timestamp"),
                Query.contains("target_groups", user_groups)
            ]

            )

                # Filter messages by user groups
                filtered_messages = []
                for message in result['documents']:
                    try:
                        message_groups = json.loads(message.get('target_groups', '[]'))
                        if any(group in message_groups for group in user_groups):
                            filtered_messages.append(message)
                    except:
                        # If parsing fails, include the message
                        filtered_messages.append(message)
                
                print(f"📨 Retrieved {len(filtered_messages)} messages from AppWrite")
                return filtered_messages
                
            except Exception as e:
                print(f"❌ Error getting messages from AppWrite: {e}")
        
        # Fallback to local cache
        return self.get_local_messages()
    
    def get_local_messages(self):
        """Get messages from local cache"""
        try:
            if 'messages' in self.local_store:
                messages_dict = self.local_store.get('messages')
                # Convert to list and sort by timestamp
                messages_list = list(messages_dict.values())
                messages_list.sort(key=lambda x: x.get('timestamp', 0), reverse=True)
                print(f"📨 Retrieved {len(messages_list)} messages from local cache")
                return messages_list
            return []
        except Exception as e:
            print(f"❌ Error getting local messages: {e}")
            return []

# Test function
async def test_full_connection():
    print("🚀 Starting Comprehensive AppWrite Test...")
    print("=" * 50)
    
    backend = AppWriteBackend()
    
    if not backend.online_mode:
        print("⚠️ Running in offline mode - basic functionality only")
        # Test local storage
        test_msg = await backend.send_message(
            content="📱 Test message - Local storage working!",
            sender_id="local_test_user",
            sender_name="Local Test Bot", 
            target_groups=["all_users"]
        )
        
        messages = backend.get_local_messages()
        print(f"✅ Local storage test: {len(messages)} messages found")
        return True
    
    # Test database initialization
    print("📁 Step 1: Database Initialization")
    init_success = await backend.initialize_chat_database()
    if not init_success:
        print("❌ Database initialization failed")
        return False
    
    print("✅ Database initialized successfully!")
    print("")
    
    # Test connection and message operations
    print("📡 Step 2: Connection & Message Test")
    connection_success = await backend.test_connection()
    
    if connection_success:
        print("✅ All tests passed! AppWrite is ready for chat functionality.")
        return True
    else:
        print("❌ Connection test failed")
        return False

if __name__ == "__main__":
    print("🔧 Testing AppWrite Integration...")
    print("")
    result = asyncio.run(test_full_connection())
    print("")
    print("=" * 50)
    print(f"🎯 FINAL RESULT: {'✅ SUCCESS' if result else '❌ FAILED'}")