"""
ClientCode.py - Complete Signal Protocol E2EE Chat Client

This client implements the FULL Signal Protocol for End-to-End Encryption:
1. X3DH Key Exchange (Identity Key, Signed Pre-Key, One-Time Pre-Keys, Ephemeral Key)
2. Double Ratchet Algorithm for Perfect Forward Secrecy
3. Ed25519 Signatures for Key Authentication
4. Safety Numbers for Identity Verification

Author: University Cryptography Project - Full Signal Implementation
"""

import socket
import sys
import threading
import errno
import json

from PyQt5 import QtCore, QtGui
from PyQt5.QtCore import QPropertyAnimation, QTimer
from PyQt5.QtGui import QIcon, QImage
from PyQt5.QtWidgets import QMainWindow, QApplication, QPushButton, QFileDialog, QMenu, QTextEdit, QMessageBox

import os
import sys

sys.path.append(os.path.join(os.path.dirname(__file__), '../'))

from Client.Bubble.LabelBubble import MessageDelegate, MessageModel, USER_ME, USER_THEM, USER_ADMIN
from Client.Username.Choose_Draggable import Draggable
from Client.Client_UI import Ui_MainWindow

# Import Complete Signal Protocol Crypto Module
from Client.crypto_utils import CryptoManager, PreKeyBundle, KeyFingerprint

import random
import colorsys
from time import time
# import uuid

# from PIL import Image as PillowImage

import ast

from DropButton.dropbutton import DropButton

HOST = '127.0.0.1'
PORT = 1234
# Server Messages
s_messages = ('connected to the server!', 'disconnected from the server!')
HEADER_LENGTH = 8192

# Complete Signal Protocol Message Types
MSG_TYPE_PUB_KEY_UPLOAD = 'PUB_KEY_UPLOAD'
MSG_TYPE_PREKEY_BUNDLE_UPLOAD = 'PREKEY_BUNDLE_UPLOAD'
MSG_TYPE_GET_ALL_PUB_KEYS = 'GET_ALL_PUB_KEYS'
MSG_TYPE_GET_PREKEY_BUNDLE = 'GET_PREKEY_BUNDLE'
MSG_TYPE_E2EE_MESSAGE = 'E2EE_MESSAGE'


# ============ Helpers ==============
# Random Color Generator
def rand_color():
    h, s, l = random.uniform(0, 360) / 360, random.uniform(0.2, 1), random.uniform(0.5, 1)
    r, g, b = [int(256 * i) for i in colorsys.hls_to_rgb(h, l, s)]
    return '#%02X%02X%02X' % (r, g, b)


# def fancy_dict(*args):
#     'Pass in a list of tuples, which will be key/value pairs'
#     ret = {}
#     for k, v in args:
#         for i in k:
#             ret[i] = v
#     return ret
#

# Find Character at a given position
def find_nth_overlapping(haystack, needle, n):
    start = haystack.find(needle)
    while start >= 0 and n > 1:
        start = haystack.find(needle, start + 1)
        n -= 1
    return start


# Client List
clientColor = dict()
clientUser = list()
clientList = list()
fragments = list()


def set_message_color(username):
    clientList.append(username)
    for names in clientList:
        if names not in clientColor:
            clientColor[names] = rand_color()


class ClientCode(Ui_MainWindow, QMainWindow):
    def __init__(self, host, port):
        super(ClientCode, self).__init__()
        self.setupUi(self)
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.sock.connect((host, port))
        self.sock.setblocking(True)
        
        # Accept Username here
        self.windowAvailable = None
        self.getUsername()
        
        # ========== E2EE INITIALIZATION (Full Signal Protocol) ==========
        # Step 1: Initialize CryptoManager with our username
        # This generates:
        #   - Identity Key Pair (Ed25519 for signing + X25519 for DH)
        #   - Signed Pre-Key (X25519, signed by Identity Key)
        #   - Multiple One-Time Pre-Keys (X25519)
        self.crypto_manager = CryptoManager(self.username.decode('utf-8'))
        
        # Flag to show encryption debug info (useful for demonstrating E2EE)
        self.show_crypto_debug = True
        
        # Track key fingerprints for safety number verification
        self.verified_fingerprints = {}
        
        # ========== END E2EE INITIALIZATION ==========
        
        # Set threading here
        self.gui_done = True
        self.running = True
        self.create_emojis()
        # self.myPixmap = QPixmap(600, 600)
        self.uiFunctions()
        self.threading()
        self.bubbleChat()
        self.send_server_messages()
        
        # ========== E2EE: Register Pre-Key Bundle with Server ==========
        # Step 2: Upload our Pre-Key Bundle to the server
        # This includes: Identity Key, Signed Pre-Key, One-Time Pre-Keys
        self.upload_prekey_bundle()
        
        # Step 3: Request all other users' public keys (for UI display)
        # Pre-Key Bundles will be fetched on-demand when sending messages
        QTimer.singleShot(500, self.request_all_public_keys)

    def threading(self):
        receive_thread = threading.Thread(target=self.receive)
        receive_thread.start()

    def create_emojis(self):
        buttons = {}
        for i in range(27):  # controls rows
            for j in range(6):  # controls columns
                # keep a reference to the buttons
                buttons[(i, j)] = QPushButton(self.Emo_Smiles)
                buttons[(i, j)].setObjectName(f'emoji_{j}_smiles')
                buttons[(i, j)].setCursor(QtGui.QCursor(QtCore.Qt.PointingHandCursor))
                buttons[(i, j)].setFlat(True)
                # add to the layout
                self.gridLayout_2.addWidget(buttons[(i, j)], i, j)
        # Display Emojis
        icons = []
        curr_moji_length = len(self.Emo_Smiles.children()[1:162]) + 1
        for items in range(0, curr_moji_length):
            icon = QIcon()
            icon.addPixmap(QtGui.QPixmap(f":/EmojisOpened/emoji_{items}.png"), QtGui.QIcon.Normal,
                           QtGui.QIcon.Off)
            icons.append(icon)
        for index, item in enumerate(self.Emo_Smiles.children()[1:163]):
            item.setIcon(icons[index])
            item.setIconSize(QtCore.QSize(32, 32))

        self.create_emojis_dropdown()

    def create_emojis_dropdown(self):
        buttons = {}
        for i in range(27, 34):  # controls rows example: range(27, 34) means 7 rows
            for j in range(6):  # controls columns
                # keep a reference to the buttons
                buttons[(i, j)] = DropButton(self.Emo_Smiles)
                buttons[(i, j)].setObjectName(f'emoji_{j}_smiles')
                buttons[(i, j)].setCursor(QtGui.QCursor(QtCore.Qt.PointingHandCursor))
                buttons[(i, j)].setFlat(True)
                # add to the layout
                self.gridLayout_2.addWidget(buttons[(i, j)], i, j)
        # Display Emojis
        icons = []
        # Affect Only Emojis 162 to 205 or the first 42 emojis (for testing)
        curr_moji_length = len(self.Emo_Smiles.children()[163:205])

        initial_counter = 163
        for items in range(0, curr_moji_length):
            icon = QIcon()
            icon.addPixmap(QtGui.QPixmap(f":/Yellow/emoji_{initial_counter}.png"), QtGui.QIcon.Normal,
                           QtGui.QIcon.Off)
            initial_counter += 6
            # if initial_counter == 385:
            #     initial_counter = 405
            icons.append(icon)

        for index, item in enumerate(self.Emo_Smiles.children()[163:205]):
            item.setIcon(icons[index])
            item.setIconSize(QtCore.QSize(32, 32))
        # Set dynamic button before sub menu here from dynamic emojis list which contains all yellows
        for index, item in enumerate(self.Emo_Smiles.children()[163:205]):  # starts from button 163 to 205
            item.clicked.connect(lambda checked, text=index: self.textEdit.insertPlainText(self.dynamic_emojis[text]))

        self.dynamic_emojis_menu()

    def dynamic_emojis_menu(self):
        # item.clicked.connect(lambda checked, text=index: self.textEdit.insertPlainText(self.emojis[text]))
        button_index = 164
        emoji_index = 0
        jump = [i for i in range(163, 424, 6)]
        # jump_icon = [i for i in range(385,404)]
        display_icons = []

        # Set Icons HEre
        for items in range(164, 424):
            icon = QIcon()
            icon.addPixmap(QtGui.QPixmap(f":/EmojisOpened/emoji_{items}.png"))
            # print(items)
            display_icons.append(icon)
        # Set actions for sub menus here
        for button in self.Emo_Smiles.children()[163:424]:
            self.menu_emoji = QMenu()
            if button_index in jump:
                button_index += 1
                emoji_index += 1
            self.menu_emoji.addAction(display_icons[emoji_index], "",
                                      lambda index=button_index: self.textEdit.insertPlainText(self.emojis[index]))
            button_index += 1
            emoji_index += 1
            self.menu_emoji.addAction(display_icons[emoji_index], "",
                                      lambda index=button_index: self.textEdit.insertPlainText(self.emojis[index]))
            button_index += 1
            emoji_index += 1
            self.menu_emoji.addAction(display_icons[emoji_index], "",
                                      lambda index=button_index: self.textEdit.insertPlainText(self.emojis[index]))
            button_index += 1
            emoji_index += 1
            self.menu_emoji.addAction(display_icons[emoji_index], "",
                                      lambda index=button_index: self.textEdit.insertPlainText(self.emojis[index]))
            button_index += 1
            emoji_index += 1
            self.menu_emoji.addAction(display_icons[emoji_index], "",
                                      lambda index=button_index: self.textEdit.insertPlainText(self.emojis[index]))
            button_index += 1
            emoji_index += 1
            button.setMenu(self.menu_emoji)

    def uiFunctions(self):
        self.Hamburger.clicked.connect(self.slide_left_menu)
        self.Send_Button.clicked.connect(self.write)
        self.emojiButton.clicked.connect(self.emoji_pane)
        self.attachButton.clicked.connect(self.send_image)
        # Emojis
        # Get emojis from text file
        self.emojis = []

        self.textEdit.document()
        # cursor = QTextCursor(textArea)
        with open('EmojiList.txt', 'r', encoding="utf8") as file:
            self.emojis = file.read().splitlines()
        for index, item in enumerate(self.Emo_Smiles.children()[1:163]):
            # Add option to insert html image instead of plain text after inserting images in qlistview
            item.clicked.connect(lambda checked, text=index: self.textEdit.insertPlainText(self.emojis[text]))
            # item.clicked.connect(lambda checked, text=index: cursor.insertImage(f":/EmojisOpened/emoji_{text}.png"))
        self.dynamic_emojis = self.emojis[163::6]
        # print(self.dynamic_emojis)
        # Add a timer to keep refreshing the Qlistview
        self.timer = QTimer()
        self.timer.timeout.connect(lambda: self.model.layoutChanged.emit())
        self.timer.start(150)
        
        # ========== E2EE: Add Crypto Debug Toggle Button ==========
        # This button toggles display of encryption/decryption details
        # Useful for demonstrating E2EE to professor
        self.setup_crypto_debug_ui()

    def getUsername(self):
        if self.windowAvailable is None:
            self.windowAvailable = Draggable()
        if self.windowAvailable.exec_():
            self.username = self.windowAvailable.lineEdit.text().encode('utf-8')
            self.username_header = f'{len(self.username):<{HEADER_LENGTH}}'.encode('utf-8')
            self.sock.send(self.username_header + self.username)
            self.UserNickname.setText(self.username.decode('utf-8'))
        self.windowAvailable = None

    def send_server_messages(self, s_msg_type="Connected"):
        """Send server messages upon connecting to server or disconnecting"""
        if s_msg_type == "Connected":
            message = f"{self.username} > connected to the server! \n".encode('utf-8')
            message_header = f'{len(message):< {HEADER_LENGTH}}'.encode('utf-8')
            self.sock.send(message_header + message)
            self.model.add_message(USER_ADMIN, "You Connected To the Server", time(), self.username.decode('utf-8'),
                                   "#ffffff")
            # Display E2EE status
            self.model.add_message(USER_ADMIN, "🔐 E2EE Enabled (Full Signal Protocol)", time(), "System", "#00ff00")
            self.model.add_message(USER_ADMIN, "  ├─ X3DH Key Exchange", time(), "System", "#00ff00")
            self.model.add_message(USER_ADMIN, "  ├─ Double Ratchet Algorithm", time(), "System", "#00ff00")
            self.model.add_message(USER_ADMIN, "  └─ AES-256-GCM Encryption", time(), "System", "#00ff00")
        elif s_msg_type == "Disconnected":
            message = f"{self.username} > disconnected from the server! \n".encode('utf-8')
            message_header = f'{len(message):< {HEADER_LENGTH}}'.encode('utf-8')
            self.sock.send(message_header + message)

    # ========== E2EE PROTOCOL METHODS (Full Signal Protocol) ==========
    
    def setup_crypto_debug_ui(self):
        """
        Setup UI elements for demonstrating E2EE encryption.
        Prints initialization information to console.
        """
        print("=" * 70)
        print("E2EE Client Initialized (Full Signal Protocol)")
        print("=" * 70)
        print(f"Username: {self.username.decode('utf-8')}")
        print(f"Identity Public Key: {self.crypto_manager.get_identity_key_b64()[:32]}...")
        print(f"Signed Pre-Key ID: {self.crypto_manager.signed_prekey.key_id}")
        print(f"One-Time Pre-Keys: {len(self.crypto_manager.one_time_prekeys)} available")
        print("-" * 70)
        print("Protocol Components:")
        print("  • X3DH (Extended Triple Diffie-Hellman) Key Exchange")
        print("  • Double Ratchet Algorithm (DH + Symmetric Ratchets)")
        print("  • AES-256-GCM Authenticated Encryption")
        print("  • HKDF-SHA256 Key Derivation")
        print("  • Ed25519 Digital Signatures")
        print("=" * 70)
    
    def upload_prekey_bundle(self):
        """
        Upload our Pre-Key Bundle to the server.
        
        Pre-Key Bundle contains:
        - Identity Public Key (for long-term identity)
        - Signed Pre-Key (medium-term, signed by Identity Key)
        - One-Time Pre-Keys (ephemeral, used once)
        
        This is the Signal Protocol's way of enabling asynchronous
        key exchange - other users can establish sessions with us
        even when we're offline.
        """
        bundle = self.crypto_manager.get_prekey_bundle_for_server()
        
        bundle_upload_msg = json.dumps({
            'type': MSG_TYPE_PREKEY_BUNDLE_UPLOAD,
            'username': self.username.decode('utf-8'),
            'prekey_bundle': bundle  # Server expects 'prekey_bundle' not 'bundle'
        })
        
        message_bytes = bundle_upload_msg.encode('utf-8')
        message_header = f'{len(message_bytes):< {HEADER_LENGTH}}'.encode('utf-8')
        self.sock.send(message_header + message_bytes)
        
        print(f"[E2EE] ✓ Uploaded Pre-Key Bundle to server")
        print(f"[E2EE]   Identity Key: {bundle['identity_key'][:24]}...")
        print(f"[E2EE]   Signed Pre-Key ID: {bundle['signed_prekey_id']}")
        print(f"[E2EE]   One-Time Pre-Keys: {len(bundle['one_time_prekeys'])}")
    
    def request_prekey_bundle(self, target_username: str):
        """
        Request a user's Pre-Key Bundle from the server.
        This is needed to establish an X3DH session with them.
        
        Args:
            target_username: The username to get the bundle for
        """
        request_msg = json.dumps({
            'type': MSG_TYPE_GET_PREKEY_BUNDLE,
            'target_username': target_username
        })
        
        message_bytes = request_msg.encode('utf-8')
        message_header = f'{len(message_bytes):< {HEADER_LENGTH}}'.encode('utf-8')
        self.sock.send(message_header + message_bytes)
        
        print(f"[E2EE] Requested Pre-Key Bundle for '{target_username}'")
    
    def request_all_public_keys(self):
        """
        Request all users' identity public keys from server.
        This is for UI display (showing available users).
        Actual session establishment uses Pre-Key Bundles.
        """
        request_msg = json.dumps({
            'type': MSG_TYPE_GET_ALL_PUB_KEYS
        })
        
        message_bytes = request_msg.encode('utf-8')
        message_header = f'{len(message_bytes):< {HEADER_LENGTH}}'.encode('utf-8')
        self.sock.send(message_header + message_bytes)
        
        print(f"[E2EE] Requested all public keys from server")
    
    def handle_key_update(self, message: str):
        """
        Handle server notification about new user key registration.
        
        NOTE: We do NOT auto-request bundles here anymore!
        Sessions are established on-demand when sending messages.
        
        Args:
            message: The KEY_UPDATE or BUNDLE_UPDATE message from server
        """
        try:
            # Parse the notification
            if "KEY_UPDATE:" in message:
                json_str = message.replace("KEY_UPDATE:", "").strip()
            elif "BUNDLE_UPDATE:" in message:
                json_str = message.replace("BUNDLE_UPDATE:", "").strip()
            else:
                json_str = message
            
            data = json.loads(json_str)
            new_username = data.get('username')
            
            if new_username and new_username != self.username.decode('utf-8'):
                print(f"[E2EE] New user '{new_username}' is now available for secure chat")
                # Store in known_users for later
                if not hasattr(self, 'known_users'):
                    self.known_users = set()
                self.known_users.add(new_username)
            
            # Refresh public keys list
            self.request_all_public_keys()
            
        except Exception as e:
            print(f"[E2EE] Error handling key update: {e}")
    
    def handle_pub_keys_response(self, message: str):
        """
        Handle server response containing all users' identity public keys.
        
        NOTE: We do NOT auto-establish sessions here anymore!
        Sessions are established on-demand when sending messages,
        or when receiving an initial X3DH message.
        
        Args:
            message: The PUB_KEYS response from server
        """
        try:
            json_str = message.replace("PUB_KEYS:", "").strip()
            data = json.loads(json_str)
            
            if data.get('type') == 'ALL_PUB_KEYS':
                keys = data.get('keys', {})
                my_username = self.username.decode('utf-8')
                print(f"[E2EE] Received {len(keys)} identity public keys from server")
                
                # Store known users for later session establishment
                for username, pub_key_b64 in keys.items():
                    if username != my_username:
                        print(f"[E2EE]   • '{username}' available for secure chat")
                        # Store in known_users but don't establish session yet
                        if not hasattr(self, 'known_users'):
                            self.known_users = set()
                        self.known_users.add(username)
                        
        except Exception as e:
            print(f"[E2EE] Error handling public keys response: {e}")
    
    def handle_prekey_bundle_response(self, message: str):
        """
        Handle server response containing a user's Pre-Key Bundle.
        Uses X3DH to establish a session with that user.
        
        Args:
            message: The PREKEY_BUNDLE response from server
        """
        try:
            json_str = message.replace("PREKEY_BUNDLE:", "").strip()
            data = json.loads(json_str)
            
            if data.get('type') == 'PREKEY_BUNDLE_RESPONSE':
                target_username = data.get('target_username')
                bundle = data.get('bundle')
                
                if bundle:
                    print(f"\n[E2EE] ═══════════════════════════════════════════════")
                    print(f"[E2EE] Received Pre-Key Bundle for '{target_username}'")
                    print(f"[E2EE] ═══════════════════════════════════════════════")
                    
                    # Import the bundle and establish X3DH session
                    success = self.crypto_manager.import_prekey_bundle(target_username, bundle)
                    
                    if success:
                        print(f"[E2EE] ✓ X3DH session established with '{target_username}'")
                        
                        # Display safety number for verification
                        fingerprint = self.crypto_manager.get_key_fingerprint(target_username)
                        if fingerprint:
                            print(f"[E2EE] Safety Number: {fingerprint[:20]}...")
                        
                        # Remove from pending requests
                        if hasattr(self, 'pending_bundle_requests'):
                            self.pending_bundle_requests.discard(target_username)
                            remaining = len(self.pending_bundle_requests)
                            if remaining > 0:
                                print(f"[E2EE] ⏳ Waiting for {remaining} more bundle(s)...")
                        
                        # If there's a pending message AND all bundles received, send it now
                        if hasattr(self, 'pending_message') and self.pending_message:
                            pending_requests = getattr(self, 'pending_bundle_requests', set())
                            if len(pending_requests) == 0:
                                pending = self.pending_message
                                self.pending_message = None
                                print(f"[E2EE] 📤 All sessions established! Sending queued message...")
                                self.encrypt_and_send_message(pending)
                                # Update UI with our sent message
                                self.model.add_message(USER_ME, pending, time(), self.username.decode('utf-8'), "#90caf9")
                    else:
                        print(f"[E2EE] ✗ Failed to establish session with '{target_username}'")
                        # Remove from pending even on failure to prevent hanging
                        if hasattr(self, 'pending_bundle_requests'):
                            self.pending_bundle_requests.discard(target_username)
                else:
                    print(f"[E2EE] ✗ No Pre-Key Bundle available for '{target_username}'")
                    # Remove from pending even if no bundle available
                    if hasattr(self, 'pending_bundle_requests'):
                        self.pending_bundle_requests.discard(target_username)
                        
        except Exception as e:
            print(f"[E2EE] Error handling Pre-Key Bundle response: {e}")
            import traceback
            traceback.print_exc()
    
    def encrypt_and_send_message(self, plaintext: str):
        """
        Encrypt a message using the Double Ratchet algorithm and send it.
        
        Full Signal Protocol Encryption Flow:
        1. If no session exists with any peer, request bundles and queue message
        2. Use X3DH to derive initial root key (if first message)
        3. Use Double Ratchet to derive message key
        4. Encrypt message with AES-256-GCM
        5. Include ratchet public key for recipient to advance ratchet
        
        NOTE: Only the SENDER initiates X3DH. The receiver will establish
        their session from the X3DH header in the received message.
        
        Args:
            plaintext: The message to encrypt and send
        """
        username_str = self.username.decode('utf-8')
        known_users = getattr(self, 'known_users', set())
        
        # Check if we have sessions with known users who we want to message
        users_without_sessions = [u for u in known_users if u not in self.crypto_manager.sessions]
        
        if users_without_sessions:
            # Some users don't have sessions yet - need to establish them
            # Initialize pending tracking attributes
            if not hasattr(self, 'pending_message'):
                self.pending_message = None
            if not hasattr(self, 'pending_bundle_requests'):
                self.pending_bundle_requests = set()
            
            if self.pending_message is None:
                # First attempt - request bundles and queue the message
                self.pending_message = plaintext
                self.pending_bundle_requests = set(users_without_sessions)
                print(f"[E2EE] No sessions with {len(users_without_sessions)} user(s). Requesting Pre-Key Bundles...")
                print(f"[E2EE] Your message will be sent after all sessions are established.")
                for user in users_without_sessions:
                    self.request_prekey_bundle(user)
                return
            else:
                # Bundles requested but sessions not yet established
                print(f"[E2EE] ⏳ Still waiting for {len(self.pending_bundle_requests)} session(s)...")
                print(f"[E2EE] Please wait a moment and try again.")
                return
        
        # Clear pending message since we now have sessions with everyone
        if hasattr(self, 'pending_message'):
            self.pending_message = None
        if hasattr(self, 'pending_bundle_requests'):
            self.pending_bundle_requests = set()
        
        if not known_users:
            print(f"[E2EE] ⚠ No other users available")
            message = f"{username_str} > {plaintext} \n".encode('utf-8')
            message_header = f'{len(message):< {HEADER_LENGTH}}'.encode('utf-8')
            self.sock.send(message_header + message)
            return
        
        # Encrypt the message for all peers with active sessions
        encrypted_payload = self.crypto_manager.encrypt_message(plaintext, username_str)
        
        if encrypted_payload:
            json_message = self.crypto_manager.serialize_payload(encrypted_payload)
            
            # Debug output
            if self.show_crypto_debug:
                print("\n" + "═" * 70)
                print("OUTGOING ENCRYPTED MESSAGE (Double Ratchet)")
                print("═" * 70)
                print(self.crypto_manager.get_encryption_debug_info(encrypted_payload))
            
            # Send encrypted message
            message_bytes = json_message.encode('utf-8')
            message_header = f'{len(message_bytes):< {HEADER_LENGTH}}'.encode('utf-8')
            self.sock.send(message_header + message_bytes)
            
            print(f"[E2EE] ✓ Sent encrypted message ({len(json_message)} bytes)")
        else:
            # No sessions available
            print(f"[E2EE] ⚠ No peers with active sessions, sending unencrypted")
            message = f"{username_str} > {plaintext} \n".encode('utf-8')
            message_header = f'{len(message_bytes):< {HEADER_LENGTH}}'.encode('utf-8')
            self.sock.send(message_header + message)
    
    def decrypt_received_message(self, raw_message: str, sender: str) -> tuple:
        """
        Decrypt a received message using Double Ratchet.
        
        Full Signal Protocol Decryption Flow:
        1. Parse the encrypted message JSON
        2. If this is a new session, use X3DH to derive initial keys
        3. Use Double Ratchet to derive the message key
        4. Decrypt with AES-256-GCM
        5. Advance ratchet state for forward secrecy
        
        Args:
            raw_message: The raw message string (may be encrypted JSON)
            sender: The sender's username
            
        Returns:
            Tuple of (decrypted_message, was_encrypted)
        """
        try:
            # Try to parse as E2EE message
            payload = CryptoManager.deserialize_payload(raw_message)
            
            if payload:
                print("\n" + "═" * 70)
                print("INCOMING ENCRYPTED MESSAGE (Double Ratchet)")
                print("═" * 70)
                print(f"From: {payload.get('sender')}")
                print(f"Message Number: {payload.get('message_number', 'N/A')}")
                print(f"Ciphertext: {payload.get('ciphertext', '')[:40]}...")
                
                # Check if this is an initial X3DH message
                if payload.get('x3dh_header'):
                    print(f"[E2EE] Initial X3DH message detected")
                    print(f"[E2EE] Processing X3DH key exchange...")
                
                # Decrypt the message
                decrypted = self.crypto_manager.decrypt_message(payload)
                
                if decrypted:
                    print(f"[E2EE] ✓ Successfully decrypted message from '{sender}'")
                    print(f"[E2EE]   Plaintext: {decrypted[:50]}{'...' if len(decrypted) > 50 else ''}")
                    print("═" * 70)
                    return decrypted, True
                else:
                    print(f"[E2EE] ✗ Failed to decrypt message from '{sender}'")
                    return "[Decryption Failed - Keys may be out of sync]", True
            else:
                # Not an encrypted message
                return raw_message, False
                
        except Exception as e:
            print(f"[E2EE] Error during decryption: {e}")
            import traceback
            traceback.print_exc()
            return raw_message, False
    
    def show_safety_number(self, peer_username: str):
        """
        Display the safety number for a peer.
        This can be used to verify the encryption with that user.
        
        Args:
            peer_username: The peer's username
        """
        fingerprint = self.crypto_manager.get_key_fingerprint(peer_username)
        if fingerprint:
            print(f"\n╔══════════════════════════════════════════════════════╗")
            print(f"║          SAFETY NUMBER VERIFICATION                    ║")
            print(f"║  Your conversation with: {peer_username:<25}  ║")
            print(f"╠══════════════════════════════════════════════════════╣")
            formatted = " ".join([fingerprint[i:i+4] for i in range(0, len(fingerprint), 4)])
            print(f"║  {formatted[:52]:<52}  ║")
            if len(formatted) > 52:
                print(f"║  {formatted[52:]:<52}  ║")
            print(f"╚══════════════════════════════════════════════════════╝")
        else:
            print(f"[E2EE] No safety number available for '{peer_username}'")

    # ========== END E2EE PROTOCOL METHODS ==========

    def write(self):
        """
        This function gets the message and sends it ENCRYPTED to the server.
        
        Full Signal Protocol Encryption Flow:
        1. Check if we have an active Double Ratchet session with peers
        2. If not, request Pre-Key Bundles and establish X3DH sessions
        3. Use Double Ratchet to derive message keys (forward secrecy)
        4. Encrypt with AES-256-GCM
        5. Include DH ratchet key for recipient to advance ratchet
        """
        plaintext = self.textEdit.toPlainText()
        
        if not plaintext.strip():
            return  # Don't send empty messages
        
        # Check for special commands
        if plaintext.startswith("/safety "):
            # Show safety number for a user
            peer = plaintext.replace("/safety ", "").strip()
            self.show_safety_number(peer)
            self.textEdit.clear()
            return
        
        if plaintext.startswith("/connect "):
            # Request pre-key bundle for a user to establish session
            peer = plaintext.replace("/connect ", "").strip()
            self.request_prekey_bundle(peer)
            self.model.add_message(USER_ADMIN, f"Requesting secure session with '{peer}'...", time(), "System", "#ffff00")
            self.textEdit.clear()
            return
        
        # ========== E2EE: Encrypt and send the message ==========
        # Check if message will be pending (some users don't have sessions)
        known_users = getattr(self, 'known_users', set())
        users_without_sessions = [u for u in known_users if u not in self.crypto_manager.sessions]
        will_be_pending = len(users_without_sessions) > 0
        
        self.encrypt_and_send_message(plaintext)
        
        # Only update local UI if message was actually sent (not pending)
        # Pending messages will update UI in handle_prekey_bundle_response
        if not will_be_pending:
            self.model.add_message(USER_ME, plaintext, time(), self.username.decode('utf-8'), "#90caf9")
        
        self.textEdit.clear()
        self.textEdit.setHtml(self.getTextStyles)

    def send_image(self, open_file=None):
        if not open_file:
            open_file = QFileDialog.getOpenFileName(None, 'Open File:', '', 'Images (*.png *.jpg)')
        if open_file[0]:
            with open(open_file[0], 'rb') as file:
                openFile_ok = file.read()
                image = QImage()
                image.loadFromData(openFile_ok)
                # For now use arbitrary message "sentIMage to denote message sent"
                message = f"{self.username} > {openFile_ok} \n".encode('utf-8')
                message_header = f'{len((message)):< {HEADER_LENGTH}}'.encode('utf-8')
                self.sock.send(message_header + message)
                self.model.add_message(USER_ME, "Sent Image", time(), self.username.decode('utf-8'), "#90caf9", image)
                self.textEdit.clear()
                self.textEdit.setHtml(self.getTextStyles)
        else:
            pass

    def receive(self):
        """
        Receive messages from the server and handle E2EE decryption.
        
        Full Signal Protocol Decryption Flow:
        1. Detect if message is encrypted (JSON with type "E2EE_MESSAGE")
        2. Check for X3DH header (indicates new session)
        3. If new session: process X3DH to derive initial root key
        4. Use Double Ratchet to derive message key
        5. Decrypt with AES-256-GCM
        6. Advance ratchet state (forward secrecy)
        7. Display decrypted message in UI
        """
        try:
            while True:
                username_header = self.sock.recv(HEADER_LENGTH)
                if not len(username_header):
                    print("Connection closed by the server")
                    sys.exit()
                    
                # Get USERNAME
                username_length = int(username_header.decode('utf-8').strip())
                username = self.sock.recv(username_length).decode('utf-8')
                
                # AFTER GETTING USERNAME GET COLOR
                set_message_color(username)
                
                # GET MESSAGE HERE
                message_header = self.sock.recv(HEADER_LENGTH)
                message_length = int(message_header.decode('utf-8').strip())
                message = self.sock.recv(message_length).decode('utf-8')
                
                # ========== E2EE: Handle Protocol Messages ==========
                
                # Check for server protocol messages
                if username == "[SERVER]":
                    if message.startswith("KEY_UPDATE:") or message.startswith("BUNDLE_UPDATE:"):
                        self.handle_key_update(message)
                        continue
                    elif message.startswith("PUB_KEYS:"):
                        self.handle_pub_keys_response(message)
                        continue
                    elif message.startswith("PREKEY_BUNDLE:"):
                        self.handle_prekey_bundle_response(message)
                        continue
                
                # ========== E2EE: Attempt to Decrypt Message ==========
                
                # Try to decrypt the message (will return original if not encrypted)
                decrypted_message, was_encrypted = self.decrypt_received_message(message, username)
                
                if was_encrypted:
                    # Message was encrypted - show decrypted content
                    display_message = decrypted_message
                else:
                    # Not encrypted - handle as before
                    display_message = message[message.find(">") + 1:].replace(" ", "", 1) if ">" in message else message
                
                # Check if admin message (server announcement)
                if any(check in display_message.strip("\n") for check in s_messages):
                    self.model.add_message(USER_ADMIN, f'{username} {display_message}', time(), "", "#FFFFFF")
                    
                    # If a new user connected, just refresh public keys list
                    # Sessions will be established on-demand when sending messages
                    if "connected to the server" in display_message:
                        QTimer.singleShot(500, self.request_all_public_keys)
                        # Track new user
                        if username != self.username.decode('utf-8'):
                            if not hasattr(self, 'known_users'):
                                self.known_users = set()
                            self.known_users.add(username)
                else:
                    # Regular message
                    if display_message.startswith("b'"):
                        # Image data
                        image = QImage()
                        image.loadFromData(ast.literal_eval(display_message))
                        self.model.add_message(USER_THEM, "Received Image", time(), username, clientColor[username],
                                               image)
                    else:
                        # Text message - show with encryption indicator if encrypted
                        if was_encrypted:
                            # Add a lock emoji to indicate E2EE message
                            prefix = "🔐 "
                        else:
                            prefix = "⚠️ "  # Warning for unencrypted messages
                        self.model.add_message(USER_THEM, prefix + display_message, time(), username, clientColor[username])
                        
                print("Username:", username)
                print("Message:", display_message[:100] + "..." if len(display_message) > 100 else display_message)

        except IOError as e:
            if e.errno != errno.EAGAIN and e.errno != errno.EWOULDBLOCK:
                print("reading error:", str(e))
                sys.exit()

        except Exception as e:
            print('General Error:', str(e))
            import traceback
            traceback.print_exc()
            sys.exit()

    def closeEvent(self, event):
        """Close Sock and Exit application"""
        self.send_server_messages("Disconnected")
        self.running = False
        self.sock.close()
        QMainWindow.closeEvent(self, event)
        exit(0)

    def slide_left_menu(self):
        """Function To create Sliding Left Menu With QFrame"""
        width = self.SlidingMenu.width()
        if width == 50:
            new_width = 180
            self.UserLayout.setContentsMargins(-53, 0, -51, 9)
        else:
            new_width = 50
            self.UserLayout.setContentsMargins(51, 0, 51, 9)
        # Animate the transition
        self.animation = QPropertyAnimation(self.SlidingMenu, b"minimumWidth")
        self.animation.setDuration(250)
        self.animation.setStartValue(width)
        self.animation.setEndValue(new_width)
        self.animation.setEasingCurve(QtCore.QEasingCurve.InOutQuart)
        self.animation.start()

    def emoji_pane(self):
        """Function To create Sliding Left Menu With QFrame"""
        width = self.EmojiPane.width()
        if width == 0:
            new_width = 400  # 296
        else:
            new_width = 0
        # Animate the transition
        self.emoji_panel = QPropertyAnimation(self.EmojiPane, b"minimumWidth")
        self.emoji_panel.setDuration(250)
        self.emoji_panel.setStartValue(width)
        self.emoji_panel.setEndValue(new_width)
        self.emoji_panel.setEasingCurve(QtCore.QEasingCurve.InOutQuart)
        self.emoji_panel.start()

    # ---------BUBBLE STUFF--------------
    def bubbleChat(self):
        """ Attach model view to message view here, creating a list view is no longer needed as it pre-created  """
        # Start listview here
        # Use our delegate to draw items in this view.
        self.messagesView.setItemDelegate(MessageDelegate())
        self.model = MessageModel()
        self.messagesView.setModel(self.model)

    def resizeEvent(self, e):
        self.model.layoutChanged.emit()


if __name__ == "__main__":
    app = QApplication(sys.argv)
    clientCode = ClientCode(HOST, PORT)
    clientCode.show()
    sys.exit(app.exec_())
