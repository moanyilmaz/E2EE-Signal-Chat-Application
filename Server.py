"""
Server.py - Complete Signal Protocol Key Server

This server implements a complete Signal-style Key Distribution Server:
1. Stores and distributes Pre-Key Bundles (Identity Keys, Signed Pre-Keys, One-Time Pre-Keys)
2. Relays encrypted messages without decrypting them (dumb relay)
3. Manages key lifecycle (upload, fetch, deletion)

Security Note:
- The server CANNOT read message contents (End-to-End Encryption)
- It only facilitates key exchange and message relay
- All cryptographic operations happen on clients

Complete Signal Protocol Support:
- PREKEY_BUNDLE_UPLOAD: Client registers their full Pre-Key Bundle
- GET_PREKEY_BUNDLE: Client requests another user's Pre-Key Bundle for X3DH
- GET_ALL_PUB_KEYS: Client requests all connected users' identity keys
- E2EE_MESSAGE: Encrypted chat message (Double Ratchet or Sender Key)

Author: University Cryptography Project - Full Signal Implementation
"""

import socket
import select
import json
from typing import Dict, Any, Optional
from datetime import datetime

HEADER_LENGTH = 8192
IP = '127.0.0.1'
PORT = 1234

server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

server_socket.bind((IP, PORT))
server_socket.listen()

sockets_list = [server_socket]

# Client connection data: {socket: {'header': bytes, 'data': bytes}}
clients: Dict[socket.socket, Dict[str, bytes]] = {}

# ============================================================================
# SIGNAL KEY SERVER STORAGE
# ============================================================================

# Pre-Key Bundle storage (Full Signal Protocol)
# Format: {username: PreKeyBundle as dict}
prekey_bundles: Dict[str, Dict[str, Any]] = {}

# Simple public key storage (Legacy/fallback)
# Format: {username: {'socket': socket, 'public_key': public_key_b64}}
public_keys: Dict[str, Dict[str, Any]] = {}

# Reverse mapping: socket -> username
socket_to_username: Dict[socket.socket, str] = {}

# One-Time Pre-Key tracking (which OPKs have been distributed)
# Format: {username: [list of distributed OPK IDs]}
distributed_opks: Dict[str, list] = {}

# ============================================================================
# SERVER STARTUP
# ============================================================================

print("=" * 70)
print("🔐 COMPLETE SIGNAL PROTOCOL KEY SERVER")
print("=" * 70)
print(f"Server listening on {IP}:{PORT}")
print("")
print("Supported Protocol Operations:")
print("  • PREKEY_BUNDLE_UPLOAD  - Register Pre-Key Bundle (X3DH)")
print("  • GET_PREKEY_BUNDLE     - Fetch user's Pre-Key Bundle")
print("  • GET_ALL_PUB_KEYS      - List all connected users")
print("  • E2EE_MESSAGE          - Relay encrypted messages")
print("")
print("Security: Server operates as 'dumb relay' - CANNOT decrypt messages!")
print("=" * 70)


def receive_message(client_socket: socket.socket) -> Optional[Dict[str, bytes]]:
    """
    Receive a message from a client socket.
    
    Message format:
    [HEADER_LENGTH bytes for size][actual message data]
    
    Returns:
        Dictionary with 'header' and 'data' keys, or False on error
    """
    try:
        message_header = client_socket.recv(HEADER_LENGTH)
        if not len(message_header):
            return False
        message_length = int(message_header.decode('utf-8').strip())
        return {'header': message_header, 'data': client_socket.recv(message_length)}
    except:
        return False


def send_message(client_socket: socket.socket, message: str) -> bool:
    """
    Send a message to a specific client.
    
    Args:
        client_socket: Target socket
        message: String message to send
        
    Returns:
        True if sent successfully
    """
    try:
        message_bytes = message.encode('utf-8')
        message_header = f'{len(message_bytes):<{HEADER_LENGTH}}'.encode('utf-8')
        client_socket.send(message_header + message_bytes)
        return True
    except Exception as e:
        print(f"[Server] Failed to send message: {e}")
        return False


def send_to_client(client_socket: socket.socket, sender_name: str, message: str):
    """
    Send a message to a client with sender information.
    Uses the same format as regular chat messages.
    
    Args:
        client_socket: Target socket
        sender_name: Name of the sender
        message: Message content
    """
    try:
        sender_bytes = sender_name.encode('utf-8')
        sender_header = f'{len(sender_bytes):<{HEADER_LENGTH}}'.encode('utf-8')
        
        message_bytes = message.encode('utf-8')
        message_header = f'{len(message_bytes):<{HEADER_LENGTH}}'.encode('utf-8')
        
        client_socket.send(sender_header + sender_bytes + message_header + message_bytes)
    except Exception as e:
        print(f"[Server] Failed to send to client: {e}")


def handle_pub_key_upload(client_socket: socket.socket, data: Dict[str, Any]) -> None:
    """
    Handle public key registration from a client (Legacy/Simple mode).
    
    Args:
        client_socket: The client's socket
        data: JSON data containing username and public_key
    """
    username = data.get('username')
    public_key = data.get('public_key')
    
    if not username or not public_key:
        print(f"[Server] Invalid PUB_KEY_UPLOAD - missing fields")
        return
    
    # Store the public key
    public_keys[username] = {
        'socket': client_socket,
        'public_key': public_key
    }
    socket_to_username[client_socket] = username
    
    print(f"[Server] ✓ Registered identity key for '{username}'")
    print(f"[Server]   Key (truncated): {public_key[:32]}...")
    print(f"[Server]   Total registered users: {len(public_keys)}")
    
    # Notify other clients
    notify_msg = json.dumps({
        'type': 'USER_KEY_REGISTERED',
        'username': username
    })
    
    for other_socket in clients:
        if other_socket != client_socket:
            send_to_client(other_socket, "[SERVER]", f"KEY_UPDATE:{notify_msg}")


def handle_prekey_bundle_upload(client_socket: socket.socket, data: Dict[str, Any]) -> None:
    """
    Handle Pre-Key Bundle upload (Full Signal Protocol).
    
    This stores the complete Pre-Key Bundle including:
    - Identity Key (long-term)
    - Signed Pre-Key (medium-term, with signature)
    - One-Time Pre-Keys (single use)
    
    Args:
        client_socket: The client's socket
        data: JSON data containing username and prekey_bundle
    """
    username = data.get('username')
    bundle = data.get('prekey_bundle')
    
    if not username or not bundle:
        print(f"[Server] Invalid PREKEY_BUNDLE_UPLOAD - missing fields")
        return
    
    # Store the complete bundle
    prekey_bundles[username] = bundle
    socket_to_username[client_socket] = username
    
    # Also store identity key in simple format for compatibility
    if 'identity_key' in bundle:
        public_keys[username] = {
            'socket': client_socket,
            'public_key': bundle['identity_key']
        }
    
    # Initialize OPK tracking
    distributed_opks[username] = []
    
    # Check for One-Time Pre-Keys (array format)
    has_opk = bool(bundle.get('one_time_prekeys') and len(bundle.get('one_time_prekeys', [])) > 0)
    
    print(f"\n[Server] ✓ Registered Pre-Key Bundle for '{username}'")
    print(f"[Server]   Identity Key: {bundle.get('identity_key', 'N/A')[:24]}...")
    print(f"[Server]   Signed Pre-Key ID: {bundle.get('signed_prekey_id', 'N/A')}")
    print(f"[Server]   One-Time Pre-Keys: {len(bundle.get('one_time_prekeys', []))} available")
    print(f"[Server]   Total bundles registered: {len(prekey_bundles)}")
    
    # Notify other clients
    notify_msg = json.dumps({
        'type': 'USER_BUNDLE_REGISTERED',
        'username': username
    })
    
    for other_socket in clients:
        if other_socket != client_socket:
            send_to_client(other_socket, "[SERVER]", f"BUNDLE_UPDATE:{notify_msg}")


def handle_get_prekey_bundle(client_socket: socket.socket, data: Dict[str, Any]) -> None:
    """
    Handle request for a specific user's Pre-Key Bundle.
    
    This is used for X3DH session establishment.
    The server returns the bundle and optionally removes the used OPK.
    
    Args:
        client_socket: The requesting client's socket
        data: JSON data containing target_username
    """
    requester = socket_to_username.get(client_socket, 'Unknown')
    target_username = data.get('target_username')
    
    if not target_username:
        print(f"[Server] Invalid GET_PREKEY_BUNDLE - missing target_username")
        return
    
    if target_username not in prekey_bundles:
        # Try to fall back to simple key
        if target_username in public_keys:
            response = json.dumps({
                'type': 'PREKEY_BUNDLE_RESPONSE',
                'target_username': target_username,
                'bundle': None,
                'simple_key': public_keys[target_username]['public_key']
            })
            send_to_client(client_socket, "[SERVER]", f"PREKEY_BUNDLE:{response}")
        else:
            print(f"[Server] No bundle found for '{target_username}'")
            response = json.dumps({
                'type': 'PREKEY_BUNDLE_RESPONSE',
                'target_username': target_username,
                'bundle': None,
                'error': 'User not found'
            })
            send_to_client(client_socket, "[SERVER]", f"PREKEY_BUNDLE:{response}")
        return
    
    bundle = prekey_bundles[target_username].copy()
    
    # Handle One-Time Pre-Keys array - pop one OPK for the requester
    opks = bundle.get('one_time_prekeys', [])
    if opks and len(opks) > 0:
        # Get the first unused OPK
        opk_to_use = opks[0]
        opk_id = opk_to_use.get('key_id')
        
        # Track distribution
        if target_username not in distributed_opks:
            distributed_opks[target_username] = []
        distributed_opks[target_username].append(opk_id)
        
        # Remove the used OPK from the stored bundle
        prekey_bundles[target_username]['one_time_prekeys'] = opks[1:]
        
        print(f"[Server] Distributed OPK #{opk_id} for '{target_username}' to '{requester}'")
        print(f"[Server]   Remaining OPKs: {len(opks) - 1}")
    else:
        print(f"[Server] No OPKs available for '{target_username}'")
    
    response = json.dumps({
        'type': 'PREKEY_BUNDLE_RESPONSE',
        'target_username': target_username,
        'bundle': bundle
    })
    
    print(f"[Server] ✓ Sent Pre-Key Bundle for '{target_username}' to '{requester}'")
    send_to_client(client_socket, "[SERVER]", f"PREKEY_BUNDLE:{response}")


def handle_get_all_pub_keys(client_socket: socket.socket) -> None:
    """
    Handle request for all public keys from a client.
    
    Returns both full bundles and simple keys for compatibility.
    
    Args:
        client_socket: The requesting client's socket
    """
    requester = socket_to_username.get(client_socket, 'Unknown')
    
    # Compile all public keys (excluding the requester's own key)
    all_keys = {}
    for username, key_data in public_keys.items():
        if username != requester:
            all_keys[username] = key_data['public_key']
    
    response = json.dumps({
        'type': 'ALL_PUB_KEYS',
        'keys': all_keys
    })
    
    print(f"[Server] Sending {len(all_keys)} public keys to '{requester}'")
    
    # Send as a server message
    send_to_client(client_socket, "[SERVER]", f"PUB_KEYS:{response}")


def handle_protocol_message(client_socket: socket.socket, message_data: bytes) -> bool:
    """
    Check if the message is a protocol message and handle it.
    
    Supported protocol messages:
    - PUB_KEY_UPLOAD: Simple identity key registration
    - PREKEY_BUNDLE_UPLOAD: Full Signal Pre-Key Bundle registration
    - GET_ALL_PUB_KEYS: Request all users' identity keys
    - GET_PREKEY_BUNDLE: Request specific user's Pre-Key Bundle
    - E2EE_MESSAGE: Encrypted message (relayed)
    
    Args:
        client_socket: The sender's socket
        message_data: Raw message bytes
        
    Returns:
        True if this was a protocol message (handled), False if regular message
    """
    try:
        message_str = message_data.decode('utf-8')
        
        # Check if it's a JSON message
        if not message_str.strip().startswith('{'):
            return False
        
        data = json.loads(message_str)
        msg_type = data.get('type')
        
        # Simple key registration (legacy)
        if msg_type == 'PUB_KEY_UPLOAD':
            handle_pub_key_upload(client_socket, data)
            return True
        
        # Full Signal Protocol Pre-Key Bundle registration
        elif msg_type == 'PREKEY_BUNDLE_UPLOAD':
            handle_prekey_bundle_upload(client_socket, data)
            return True
        
        # Request all public keys
        elif msg_type == 'GET_ALL_PUB_KEYS':
            handle_get_all_pub_keys(client_socket)
            return True
        
        # Request specific user's Pre-Key Bundle (for X3DH)
        elif msg_type == 'GET_PREKEY_BUNDLE':
            handle_get_prekey_bundle(client_socket, data)
            return True
        
        # Encrypted message - determine protocol and log
        elif msg_type == 'E2EE_MESSAGE':
            protocol = data.get('protocol', 'SENDER_KEY')
            sender = data.get('sender', 'Unknown')
            
            print(f"\n[Server] 🔐 E2EE MESSAGE RELAY")
            print(f"[Server]    From: {sender}")
            print(f"[Server]    Protocol: {protocol}")
            
            if protocol == 'DOUBLE_RATCHET':
                messages = data.get('messages', {})
                print(f"[Server]    Recipients: {list(messages.keys())}")
                print(f"[Server]    ✓ Double Ratchet - Perfect Forward Secrecy active!")
            else:
                recipients = list(data.get('keys', {}).keys())
                ciphertext = data.get('ciphertext', '')[:40]
                print(f"[Server]    Recipients: {recipients}")
                print(f"[Server]    Ciphertext: {ciphertext}...")
            
            print(f"[Server]    🔒 Server CANNOT decrypt! (E2EE working)")
            return False  # Return False to relay as normal message
        
        return False
        
    except json.JSONDecodeError:
        return False
    except Exception as e:
        print(f"[Server] Error handling protocol message: {e}")
        import traceback
        traceback.print_exc()
        return False


def remove_client(client_socket: socket.socket) -> None:
    """
    Clean up when a client disconnects.
    
    Removes the client from all tracking data structures.
    Note: We keep the Pre-Key Bundle so others can still send to offline users.
    
    Args:
        client_socket: The disconnecting client's socket
    """
    username = socket_to_username.get(client_socket)
    if username:
        # Remove from simple key storage
        if username in public_keys:
            del public_keys[username]
        del socket_to_username[client_socket]
        
        # Note: We intentionally keep prekey_bundles[username] 
        # In real Signal, offline users can still receive messages
        
        print(f"[Server] ✗ '{username}' disconnected")
        print(f"[Server]   Pre-Key Bundle retained for offline messaging")
    
    if client_socket in clients:
        del clients[client_socket]
    
    if client_socket in sockets_list:
        sockets_list.remove(client_socket)


# Main server loop
while True:
    read_sockets, _, exception_sockets = select.select(sockets_list, [], sockets_list)
    
    for notified_socket in read_sockets:
        if notified_socket == server_socket:
            # New client connecting
            client_socket, client_address = server_socket.accept()
            
            user = receive_message(client_socket)
            if user is False:
                continue
            
            sockets_list.append(client_socket)
            clients[client_socket] = user
            
            username = user['data'].decode('utf-8')
            print(f"\n[Server] ✓ New connection: {client_address[0]}:{client_address[1]}")
            print(f"[Server]   Username: {username}")
            
        else:
            # Existing client sending a message
            message = receive_message(notified_socket)
            
            if message is False:
                # Client disconnected
                username = clients[notified_socket]['data'].decode('utf-8')
                print(f"\n[Server] ✗ Client disconnected: {username}")
                remove_client(notified_socket)
                continue
            
            user = clients[notified_socket]
            username = user['data'].decode('utf-8')
            
            # Check if this is a protocol message
            is_protocol = handle_protocol_message(notified_socket, message['data'])
            
            if not is_protocol:
                # Regular message or E2EE message - broadcast to all other clients
                try:
                    msg_preview = message['data'].decode('utf-8')[:100]
                    
                    # Check if it's an E2EE message
                    if '"type": "E2EE_MESSAGE"' in msg_preview or '"type":"E2EE_MESSAGE"' in msg_preview:
                        print(f"\n[Server] 🔐 Broadcasting encrypted message from '{username}'")
                        print(f"[Server]    (Server sees only ciphertext - E2EE active!)")
                    else:
                        print(f"\n[Server] Broadcasting from '{username}': {msg_preview}...")
                        
                except:
                    print(f"\n[Server] Broadcasting binary data from '{username}'")
                
                # Broadcast to all other clients
                for client_socket in clients:
                    if client_socket != notified_socket:
                        client_socket.send(
                            user['header'] + user['data'] + 
                            message['header'] + message['data']
                        )
    
    # Handle socket exceptions
    for notified_socket in exception_sockets:
        remove_client(notified_socket)

