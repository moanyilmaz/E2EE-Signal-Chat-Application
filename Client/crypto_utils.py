"""
crypto_utils.py - Complete Signal Protocol Implementation

This module implements a COMPLETE version of the Signal Protocol for educational purposes.
It provides the full cryptographic stack used by Signal, WhatsApp, and other secure messengers.

=== COMPLETE SIGNAL PROTOCOL COMPONENTS ===

1. X3DH (Extended Triple Diffie-Hellman) Key Agreement:
   - Identity Key (IK): Long-term identity, never changes
   - Signed Pre-Key (SPK): Medium-term, signed by IK, rotates periodically
   - One-Time Pre-Key (OPK): Single-use keys for forward secrecy
   - Ephemeral Key (EK): Per-session temporary key

2. Double Ratchet Algorithm:
   - DH Ratchet: Provides break-in recovery (post-compromise security)
   - Symmetric Ratchet: Derives unique key for each message
   - Provides both forward secrecy and break-in recovery

3. Additional Security Features:
   - Ed25519 signatures for SPK verification
   - Key fingerprints for out-of-band verification
   - Message counters for replay protection
   - Skipped message key storage for out-of-order messages

Signal Protocol Papers:
- "The X3DH Key Agreement Protocol" - Moxie Marlinspike & Trevor Perrin
- "The Double Ratchet Algorithm" - Trevor Perrin & Moxie Marlinspike

Author: University Cryptography Project - Full Implementation
"""

import os
import json
import base64
import hashlib
import hmac
from typing import Dict, Tuple, Optional, Any, List
from dataclasses import dataclass, field
from enum import Enum

# Cryptography library imports
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import x25519, ed25519
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.backends import default_backend
from cryptography.exceptions import InvalidSignature


# ============================================================================
# CONSTANTS - Signal Protocol Specifications
# ============================================================================

class SignalConstants:
    """Constants defined by Signal Protocol specification."""
    
    # Key sizes
    AES_KEY_SIZE = 32           # 256 bits for AES-256
    CHAIN_KEY_SIZE = 32         # 256 bits for chain keys
    ROOT_KEY_SIZE = 32          # 256 bits for root key
    NONCE_SIZE = 12             # 96 bits for GCM nonce
    
    # HKDF info strings (from Signal spec)
    HKDF_INFO_ROOT = b"Signal_Root_Key"
    HKDF_INFO_CHAIN = b"Signal_Chain_Key"
    HKDF_INFO_MESSAGE = b"Signal_Message_Key"
    HKDF_INFO_X3DH = b"Signal_X3DH_SharedSecret"
    
    # Pre-key configuration
    MAX_ONE_TIME_PREKEYS = 100  # Maximum OPKs to generate
    PREKEY_ROTATION_DAYS = 7   # Rotate SPK every week
    
    # Message limits
    MAX_SKIP = 1000            # Max messages to skip (prevents DoS)
    
    # Protocol identifiers
    PROTOCOL_VERSION = 3       # Signal Protocol v3


# ============================================================================
# DATA STRUCTURES
# ============================================================================

@dataclass
class KeyPair:
    """A public/private key pair for X25519."""
    private_key: x25519.X25519PrivateKey
    public_key: x25519.X25519PublicKey
    
    @classmethod
    def generate(cls) -> 'KeyPair':
        private = x25519.X25519PrivateKey.generate()
        return cls(private_key=private, public_key=private.public_key())
    
    def get_public_bytes(self) -> bytes:
        return self.public_key.public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw
        )


@dataclass
class SigningKeyPair:
    """A public/private key pair for Ed25519 signing."""
    private_key: ed25519.Ed25519PrivateKey
    public_key: ed25519.Ed25519PublicKey
    
    @classmethod
    def generate(cls) -> 'SigningKeyPair':
        private = ed25519.Ed25519PrivateKey.generate()
        return cls(private_key=private, public_key=private.public_key())
    
    def sign(self, data: bytes) -> bytes:
        return self.private_key.sign(data)
    
    def get_public_bytes(self) -> bytes:
        return self.public_key.public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw
        )


@dataclass
class SignedPreKey:
    """Signed Pre-Key with signature for verification."""
    key_id: int
    key_pair: KeyPair
    signature: bytes
    timestamp: float
    
    def get_public_bytes(self) -> bytes:
        return self.key_pair.get_public_bytes()


@dataclass
class OneTimePreKey:
    """One-Time Pre-Key for forward secrecy."""
    key_id: int
    key_pair: KeyPair
    used: bool = False
    
    def get_public_bytes(self) -> bytes:
        return self.key_pair.get_public_bytes()


@dataclass
class PreKeyBundle:
    """
    Pre-Key Bundle - Published to server for others to initiate sessions.
    
    This is what Signal calls a "key bundle" - everything needed to 
    establish a session with someone who is offline.
    """
    identity_key: bytes          # IK public key
    identity_signing_key: bytes  # For signature verification
    signed_prekey: bytes         # SPK public key
    signed_prekey_id: int
    signed_prekey_signature: bytes
    one_time_prekey: Optional[bytes] = None  # OPK public key (optional)
    one_time_prekey_id: Optional[int] = None
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            'identity_key': base64.b64encode(self.identity_key).decode(),
            'identity_signing_key': base64.b64encode(self.identity_signing_key).decode(),
            'signed_prekey': base64.b64encode(self.signed_prekey).decode(),
            'signed_prekey_id': self.signed_prekey_id,
            'signed_prekey_signature': base64.b64encode(self.signed_prekey_signature).decode(),
            'one_time_prekey': base64.b64encode(self.one_time_prekey).decode() if self.one_time_prekey else None,
            'one_time_prekey_id': self.one_time_prekey_id
        }
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'PreKeyBundle':
        return cls(
            identity_key=base64.b64decode(data['identity_key']),
            identity_signing_key=base64.b64decode(data['identity_signing_key']),
            signed_prekey=base64.b64decode(data['signed_prekey']),
            signed_prekey_id=data['signed_prekey_id'],
            signed_prekey_signature=base64.b64decode(data['signed_prekey_signature']),
            one_time_prekey=base64.b64decode(data['one_time_prekey']) if data.get('one_time_prekey') else None,
            one_time_prekey_id=data.get('one_time_prekey_id')
        )


@dataclass 
class DoubleRatchetState:
    """
    Complete Double Ratchet session state.
    
    This maintains all the state needed for the Double Ratchet algorithm:
    - DH ratchet keys for asymmetric ratcheting
    - Root key for deriving new chain keys
    - Sending/receiving chain keys for symmetric ratcheting
    - Message counters for ordering
    - Skipped message keys for out-of-order delivery
    """
    # DH Ratchet State
    dh_sending: Optional[KeyPair] = None
    dh_receiving: Optional[bytes] = None  # Peer's public key
    
    # Root Key (updated with each DH ratchet step)
    root_key: Optional[bytes] = None
    
    # Chain Keys (updated with each message)
    sending_chain_key: Optional[bytes] = None
    receiving_chain_key: Optional[bytes] = None
    
    # Message counters
    sending_message_number: int = 0
    receiving_message_number: int = 0
    previous_sending_chain_length: int = 0
    
    # Skipped message keys: {(ratchet_public_key, message_number): message_key}
    skipped_message_keys: Dict[Tuple[bytes, int], bytes] = field(default_factory=dict)
    
    # Session metadata
    session_id: Optional[str] = None
    peer_identity_key: Optional[bytes] = None
    
    def to_dict(self) -> Dict[str, Any]:
        """Serialize state for storage."""
        return {
            'dh_sending_public': base64.b64encode(self.dh_sending.get_public_bytes()).decode() if self.dh_sending else None,
            'dh_receiving': base64.b64encode(self.dh_receiving).decode() if self.dh_receiving else None,
            'root_key': base64.b64encode(self.root_key).decode() if self.root_key else None,
            'sending_chain_key': base64.b64encode(self.sending_chain_key).decode() if self.sending_chain_key else None,
            'receiving_chain_key': base64.b64encode(self.receiving_chain_key).decode() if self.receiving_chain_key else None,
            'sending_message_number': self.sending_message_number,
            'receiving_message_number': self.receiving_message_number,
            'previous_sending_chain_length': self.previous_sending_chain_length,
            'session_id': self.session_id,
            'peer_identity_key': base64.b64encode(self.peer_identity_key).decode() if self.peer_identity_key else None,
        }


# ============================================================================
# X3DH KEY AGREEMENT PROTOCOL
# ============================================================================

class X3DHKeyAgreement:
    """
    X3DH (Extended Triple Diffie-Hellman) Key Agreement Protocol.
    
    X3DH establishes a shared secret between two parties who may not be 
    online at the same time. It provides:
    - Mutual authentication
    - Forward secrecy
    - Cryptographic deniability
    
    The protocol uses four DH operations:
    DH1 = DH(IK_A, SPK_B)   - Identity to Signed Pre-Key
    DH2 = DH(EK_A, IK_B)    - Ephemeral to Identity
    DH3 = DH(EK_A, SPK_B)   - Ephemeral to Signed Pre-Key
    DH4 = DH(EK_A, OPK_B)   - Ephemeral to One-Time Pre-Key (optional)
    
    SK = KDF(DH1 || DH2 || DH3 || DH4)
    """
    
    @staticmethod
    def perform_key_agreement_initiator(
        my_identity_key: KeyPair,
        my_ephemeral_key: KeyPair,
        peer_bundle: PreKeyBundle
    ) -> Tuple[bytes, bytes]:
        """
        Initiator side of X3DH (Alice sending first message to Bob).
        
        Args:
            my_identity_key: Our long-term identity key pair
            my_ephemeral_key: Freshly generated ephemeral key pair
            peer_bundle: The recipient's pre-key bundle from server
            
        Returns:
            Tuple of (shared_secret, associated_data)
        """
        # First, verify the signed pre-key signature
        peer_signing_key = ed25519.Ed25519PublicKey.from_public_bytes(
            peer_bundle.identity_signing_key
        )
        try:
            peer_signing_key.verify(
                peer_bundle.signed_prekey_signature,
                peer_bundle.signed_prekey
            )
            print("[X3DH] ✓ Signed Pre-Key signature verified")
        except InvalidSignature:
            raise ValueError("Invalid Signed Pre-Key signature!")
        
        # Load peer's public keys
        peer_identity_key = x25519.X25519PublicKey.from_public_bytes(peer_bundle.identity_key)
        peer_signed_prekey = x25519.X25519PublicKey.from_public_bytes(peer_bundle.signed_prekey)
        
        # Perform the four DH operations
        # DH1 = DH(IK_A, SPK_B) - Our identity with their signed prekey
        dh1 = my_identity_key.private_key.exchange(peer_signed_prekey)
        print(f"[X3DH] DH1 (IK_A, SPK_B): {dh1.hex()[:16]}...")
        
        # DH2 = DH(EK_A, IK_B) - Our ephemeral with their identity
        dh2 = my_ephemeral_key.private_key.exchange(peer_identity_key)
        print(f"[X3DH] DH2 (EK_A, IK_B): {dh2.hex()[:16]}...")
        
        # DH3 = DH(EK_A, SPK_B) - Our ephemeral with their signed prekey
        dh3 = my_ephemeral_key.private_key.exchange(peer_signed_prekey)
        print(f"[X3DH] DH3 (EK_A, SPK_B): {dh3.hex()[:16]}...")
        
        # DH4 = DH(EK_A, OPK_B) - Our ephemeral with their one-time prekey (if available)
        if peer_bundle.one_time_prekey:
            peer_one_time_key = x25519.X25519PublicKey.from_public_bytes(peer_bundle.one_time_prekey)
            dh4 = my_ephemeral_key.private_key.exchange(peer_one_time_key)
            print(f"[X3DH] DH4 (EK_A, OPK_B): {dh4.hex()[:16]}...")
            dh_concat = dh1 + dh2 + dh3 + dh4
        else:
            print("[X3DH] No One-Time Pre-Key available (still secure)")
            dh_concat = dh1 + dh2 + dh3
        
        # Derive shared secret using HKDF
        shared_secret = X3DHKeyAgreement._kdf(dh_concat)
        
        # Associated data for AEAD: IK_A || IK_B
        associated_data = my_identity_key.get_public_bytes() + peer_bundle.identity_key
        
        print(f"[X3DH] ✓ Shared secret derived: {shared_secret.hex()[:16]}...")
        return shared_secret, associated_data
    
    @staticmethod
    def perform_key_agreement_responder(
        my_identity_key: KeyPair,
        my_signed_prekey: SignedPreKey,
        my_one_time_prekey: Optional[OneTimePreKey],
        peer_identity_key: bytes,
        peer_ephemeral_key: bytes
    ) -> Tuple[bytes, bytes]:
        """
        Responder side of X3DH (Bob receiving first message from Alice).
        
        Args:
            my_identity_key: Our long-term identity key pair
            my_signed_prekey: Our signed pre-key that was used
            my_one_time_prekey: Our one-time pre-key that was used (if any)
            peer_identity_key: Alice's identity public key
            peer_ephemeral_key: Alice's ephemeral public key
            
        Returns:
            Tuple of (shared_secret, associated_data)
        """
        # Load peer's public keys
        peer_ik = x25519.X25519PublicKey.from_public_bytes(peer_identity_key)
        peer_ek = x25519.X25519PublicKey.from_public_bytes(peer_ephemeral_key)
        
        # Perform the four DH operations (mirrored from initiator)
        # DH1 = DH(SPK_B, IK_A) - Our signed prekey with their identity
        dh1 = my_signed_prekey.key_pair.private_key.exchange(peer_ik)
        print(f"[X3DH] DH1 (SPK_B, IK_A): {dh1.hex()[:16]}...")
        
        # DH2 = DH(IK_B, EK_A) - Our identity with their ephemeral
        dh2 = my_identity_key.private_key.exchange(peer_ek)
        print(f"[X3DH] DH2 (IK_B, EK_A): {dh2.hex()[:16]}...")
        
        # DH3 = DH(SPK_B, EK_A) - Our signed prekey with their ephemeral
        dh3 = my_signed_prekey.key_pair.private_key.exchange(peer_ek)
        print(f"[X3DH] DH3 (SPK_B, EK_A): {dh3.hex()[:16]}...")
        
        # DH4 = DH(OPK_B, EK_A) - Our one-time prekey with their ephemeral
        if my_one_time_prekey:
            dh4 = my_one_time_prekey.key_pair.private_key.exchange(peer_ek)
            print(f"[X3DH] DH4 (OPK_B, EK_A): {dh4.hex()[:16]}...")
            dh_concat = dh1 + dh2 + dh3 + dh4
        else:
            print("[X3DH] No One-Time Pre-Key used")
            dh_concat = dh1 + dh2 + dh3
        
        # Derive shared secret using HKDF
        shared_secret = X3DHKeyAgreement._kdf(dh_concat)
        
        # Associated data: IK_A || IK_B
        associated_data = peer_identity_key + my_identity_key.get_public_bytes()
        
        print(f"[X3DH] ✓ Shared secret derived: {shared_secret.hex()[:16]}...")
        return shared_secret, associated_data
    
    @staticmethod
    def _kdf(dh_output: bytes) -> bytes:
        """Derive shared secret from concatenated DH outputs using HKDF."""
        # F || KM where F is 32 0xFF bytes (Signal spec)
        f = b'\xff' * 32
        km = f + dh_output
        
        hkdf = HKDF(
            algorithm=hashes.SHA256(),
            length=SignalConstants.ROOT_KEY_SIZE,
            salt=b'\x00' * 32,  # Zero salt for X3DH
            info=SignalConstants.HKDF_INFO_X3DH,
            backend=default_backend()
        )
        return hkdf.derive(km)


# ============================================================================
# DOUBLE RATCHET ALGORITHM
# ============================================================================

class DoubleRatchet:
    """
    Double Ratchet Algorithm Implementation.
    
    The Double Ratchet combines two ratchets:
    
    1. DH Ratchet (Asymmetric):
       - Provides "break-in recovery" / post-compromise security
       - Updates root key when DH keys change
       - Happens when conversation direction changes
    
    2. Symmetric Ratchet:
       - Provides forward secrecy for each message
       - Chain key → Message key derivation
       - Happens for every single message
    
    Properties achieved:
    - Forward Secrecy: Compromise of current keys doesn't reveal past messages
    - Break-in Recovery: Session heals after temporary compromise
    - Out-of-order Delivery: Can decrypt messages received out of order
    """
    
    def __init__(self, state: Optional[DoubleRatchetState] = None):
        self.state = state or DoubleRatchetState()
    
    def initialize_as_alice(self, shared_secret: bytes, bob_public_key: bytes) -> None:
        """
        Initialize ratchet as session initiator (Alice).
        
        Alice performs the first DH ratchet step immediately.
        
        Args:
            shared_secret: The SK from X3DH
            bob_public_key: Bob's signed pre-key (initial DH ratchet public key)
        """
        # Generate our first ratchet key pair
        self.state.dh_sending = KeyPair.generate()
        self.state.dh_receiving = bob_public_key
        
        # Perform DH and derive initial root and sending chain keys
        dh_output = self.state.dh_sending.private_key.exchange(
            x25519.X25519PublicKey.from_public_bytes(bob_public_key)
        )
        
        self.state.root_key, self.state.sending_chain_key = self._kdf_rk(
            shared_secret, dh_output
        )
        
        self.state.sending_message_number = 0
        self.state.receiving_message_number = 0
        
        print(f"[DoubleRatchet] Initialized as Alice")
        print(f"[DoubleRatchet] Root Key: {self.state.root_key.hex()[:16]}...")
    
    def initialize_as_bob(self, shared_secret: bytes, my_signed_prekey: KeyPair) -> None:
        """
        Initialize ratchet as session responder (Bob).
        
        Bob uses his signed pre-key as the initial DH key.
        
        Args:
            shared_secret: The SK from X3DH
            my_signed_prekey: Bob's signed pre-key key pair
        """
        self.state.dh_sending = my_signed_prekey
        self.state.root_key = shared_secret
        self.state.receiving_chain_key = None  # Will be set on first receive
        
        self.state.sending_message_number = 0
        self.state.receiving_message_number = 0
        
        print(f"[DoubleRatchet] Initialized as Bob")
        print(f"[DoubleRatchet] Root Key: {self.state.root_key.hex()[:16]}...")
    
    def encrypt(self, plaintext: bytes) -> Dict[str, Any]:
        """
        Encrypt a message using the Double Ratchet.
        
        Steps:
        1. Derive message key from sending chain key
        2. Encrypt plaintext with message key using AES-GCM
        3. Advance sending chain key
        4. Include current DH public key and message number in header
        
        Args:
            plaintext: The message to encrypt
            
        Returns:
            Message dict with header and ciphertext
        """
        # Derive message key from chain key
        message_key, self.state.sending_chain_key = self._kdf_ck(
            self.state.sending_chain_key
        )
        
        # Encrypt the message
        nonce = os.urandom(SignalConstants.NONCE_SIZE)
        aesgcm = AESGCM(message_key)
        ciphertext = aesgcm.encrypt(nonce, plaintext, None)
        
        # Build message
        message = {
            'header': {
                'dh_public': base64.b64encode(self.state.dh_sending.get_public_bytes()).decode(),
                'previous_chain_length': self.state.previous_sending_chain_length,
                'message_number': self.state.sending_message_number
            },
            'nonce': base64.b64encode(nonce).decode(),
            'ciphertext': base64.b64encode(ciphertext).decode()
        }
        
        # Advance message counter
        self.state.sending_message_number += 1
        
        print(f"[DoubleRatchet] Encrypted message #{message['header']['message_number']}")
        return message
    
    def decrypt(self, message: Dict[str, Any]) -> bytes:
        """
        Decrypt a message using the Double Ratchet.
        
        Steps:
        1. Check if DH ratchet step is needed (peer sent new DH key)
        2. If needed, perform DH ratchet
        3. Try to decrypt with current chain, or check skipped keys
        4. Advance receiving chain key
        
        Args:
            message: The encrypted message dict
            
        Returns:
            Decrypted plaintext
        """
        header = message['header']
        peer_dh_public = base64.b64decode(header['dh_public'])
        message_number = header['message_number']
        
        # Check if we have this message key in skipped keys
        skip_key = (peer_dh_public, message_number)
        if skip_key in self.state.skipped_message_keys:
            message_key = self.state.skipped_message_keys.pop(skip_key)
            return self._decrypt_with_key(message, message_key)
        
        # Check if this is a new DH ratchet key
        if peer_dh_public != self.state.dh_receiving:
            # Store any skipped message keys from current chain
            if self.state.receiving_chain_key is not None:
                self._skip_message_keys(
                    self.state.dh_receiving,
                    self.state.receiving_message_number,
                    header['previous_chain_length']
                )
            
            # Perform DH ratchet step
            self._dh_ratchet(peer_dh_public)
        
        # Skip any messages in current chain
        self._skip_message_keys(
            peer_dh_public,
            self.state.receiving_message_number,
            message_number
        )
        
        # Derive message key
        message_key, self.state.receiving_chain_key = self._kdf_ck(
            self.state.receiving_chain_key
        )
        
        self.state.receiving_message_number = message_number + 1
        
        print(f"[DoubleRatchet] Decrypted message #{message_number}")
        return self._decrypt_with_key(message, message_key)
    
    def _dh_ratchet(self, peer_dh_public: bytes) -> None:
        """
        Perform a DH ratchet step.
        
        This happens when we receive a message with a new DH public key.
        We derive new receiving chain key, generate new DH key pair,
        and derive new sending chain key.
        """
        print(f"[DoubleRatchet] Performing DH ratchet step")
        
        # Store previous state
        self.state.previous_sending_chain_length = self.state.sending_message_number
        self.state.sending_message_number = 0
        self.state.receiving_message_number = 0
        
        # Update receiving DH key
        self.state.dh_receiving = peer_dh_public
        peer_key = x25519.X25519PublicKey.from_public_bytes(peer_dh_public)
        
        # Derive new receiving chain key
        dh_output = self.state.dh_sending.private_key.exchange(peer_key)
        self.state.root_key, self.state.receiving_chain_key = self._kdf_rk(
            self.state.root_key, dh_output
        )
        
        # Generate new sending DH key pair
        self.state.dh_sending = KeyPair.generate()
        
        # Derive new sending chain key
        dh_output = self.state.dh_sending.private_key.exchange(peer_key)
        self.state.root_key, self.state.sending_chain_key = self._kdf_rk(
            self.state.root_key, dh_output
        )
        
        print(f"[DoubleRatchet] New root key: {self.state.root_key.hex()[:16]}...")
    
    def _skip_message_keys(self, dh_public: bytes, start: int, end: int) -> None:
        """Store skipped message keys for out-of-order delivery."""
        if self.state.receiving_chain_key is None:
            return
            
        for i in range(start, min(end, start + SignalConstants.MAX_SKIP)):
            message_key, self.state.receiving_chain_key = self._kdf_ck(
                self.state.receiving_chain_key
            )
            self.state.skipped_message_keys[(dh_public, i)] = message_key
    
    def _decrypt_with_key(self, message: Dict[str, Any], message_key: bytes) -> bytes:
        """Decrypt message with a specific message key."""
        nonce = base64.b64decode(message['nonce'])
        ciphertext = base64.b64decode(message['ciphertext'])
        
        aesgcm = AESGCM(message_key)
        return aesgcm.decrypt(nonce, ciphertext, None)
    
    @staticmethod
    def _kdf_rk(root_key: bytes, dh_output: bytes) -> Tuple[bytes, bytes]:
        """
        Root Key KDF - derives new root key and chain key.
        
        KDF_RK(rk, dh_out) = HKDF(rk, dh_out, "Root") → (new_rk, chain_key)
        """
        hkdf = HKDF(
            algorithm=hashes.SHA256(),
            length=64,  # 32 bytes each for root key and chain key
            salt=root_key,
            info=SignalConstants.HKDF_INFO_ROOT,
            backend=default_backend()
        )
        output = hkdf.derive(dh_output)
        return output[:32], output[32:]
    
    @staticmethod
    def _kdf_ck(chain_key: bytes) -> Tuple[bytes, bytes]:
        """
        Chain Key KDF - derives message key and next chain key.
        
        KDF_CK(ck) → (message_key, new_chain_key)
        
        Uses HMAC-SHA256 with different constants:
        - Message key: HMAC(ck, 0x01)
        - Next chain key: HMAC(ck, 0x02)
        """
        message_key = hmac.new(chain_key, b'\x01', hashlib.sha256).digest()
        next_chain_key = hmac.new(chain_key, b'\x02', hashlib.sha256).digest()
        return message_key, next_chain_key


# ============================================================================
# KEY FINGERPRINT
# ============================================================================

class KeyFingerprint:
    """
    Key Fingerprint Generation for Identity Verification.
    
    Signal uses "Safety Numbers" - a hash of both parties' identity keys
    that can be compared out-of-band (in person, voice call, etc.)
    to verify there's no MITM attack.
    """
    
    @staticmethod
    def generate(identity_key_1: bytes, identity_key_2: bytes) -> str:
        """
        Generate a numeric fingerprint from two identity keys.
        
        The fingerprint is the same regardless of which key is first,
        so both parties will compute the same value.
        
        Args:
            identity_key_1: First identity public key
            identity_key_2: Second identity public key
            
        Returns:
            A 60-digit fingerprint string formatted in groups of 5
        """
        # Sort keys to ensure consistent ordering
        keys = sorted([identity_key_1, identity_key_2])
        combined = keys[0] + keys[1]
        
        # Hash with SHA-512 for sufficient entropy
        digest = hashlib.sha512(combined).digest()
        
        # Convert to numeric fingerprint (using first 30 bytes → 60 digits)
        fingerprint_int = int.from_bytes(digest[:30], 'big')
        fingerprint_str = str(fingerprint_int).zfill(60)[-60:]
        
        # Format as groups of 5 digits
        groups = [fingerprint_str[i:i+5] for i in range(0, 60, 5)]
        
        return ' '.join(groups)
    
    @staticmethod
    def generate_short(identity_key: bytes) -> str:
        """
        Generate a short fingerprint for a single key (for display).
        
        Args:
            identity_key: The identity public key
            
        Returns:
            A shortened fingerprint
        """
        digest = hashlib.sha256(identity_key).hexdigest().upper()
        # Format as XX XX XX XX XX XX XX XX
        return ' '.join(digest[i:i+2] for i in range(0, 16, 2))


# ============================================================================
# COMPLETE CRYPTO MANAGER
# ============================================================================

class CryptoManager:
    """
    Complete Signal Protocol CryptoManager.
    
    This implements the FULL Signal Protocol with:
    - X3DH key exchange with signed pre-keys
    - Double Ratchet for perfect forward secrecy
    - Ed25519 signatures for authentication
    - Key fingerprints for verification
    - Pre-key management
    
    Protocol Flow:
    1. Registration: Generate IK, SPK, OPKs and publish to server
    2. Session Setup: Use X3DH to establish shared secret
    3. Messaging: Use Double Ratchet for each message
    """
    
    def __init__(self, username: str):
        """
        Initialize CryptoManager with full Signal Protocol key set.
        
        Generates:
        - Identity Key Pair (IK): Long-term, never changes
        - Identity Signing Key: Ed25519 for signing SPK
        - Signed Pre-Key (SPK): Medium-term, signed by IK
        - One-Time Pre-Keys (OPKs): Single-use keys
        """
        self.username = username
        
        # =============================================
        # IDENTITY KEYS (Long-term)
        # =============================================
        
        # X25519 Identity Key for ECDH
        self.identity_key = KeyPair.generate()
        
        # Ed25519 Identity Signing Key for signatures
        self.identity_signing_key = SigningKeyPair.generate()
        
        # =============================================
        # PRE-KEYS (Signal Protocol specific)
        # =============================================
        
        # Signed Pre-Key (rotates periodically)
        self.signed_prekey = self._generate_signed_prekey(key_id=1)
        
        # One-Time Pre-Keys (single use)
        self.one_time_prekeys: Dict[int, OneTimePreKey] = {}
        self._generate_one_time_prekeys(count=SignalConstants.MAX_ONE_TIME_PREKEYS)
        
        # =============================================
        # SESSION MANAGEMENT
        # =============================================
        
        # Active Double Ratchet sessions: {peer_username: DoubleRatchet}
        self.sessions: Dict[str, DoubleRatchet] = {}
        
        # Peer key bundles: {peer_username: PreKeyBundle}
        self.peer_bundles: Dict[str, PreKeyBundle] = {}
        
        # Legacy compatibility - simple key storage for fallback
        self.peer_public_keys: Dict[str, bytes] = {}
        self._session_key_cache: Dict[str, bytes] = {}
        
        # =============================================
        # LOGGING AND DEBUG
        # =============================================
        
        print("=" * 60)
        print(f"[CryptoManager] FULL Signal Protocol Initialized")
        print(f"[CryptoManager] Username: {username}")
        print(f"[CryptoManager] Identity Key: {self.get_public_key_bytes().hex()[:24]}...")
        print(f"[CryptoManager] Fingerprint: {self.get_fingerprint_short()}")
        print(f"[CryptoManager] Signed Pre-Key ID: {self.signed_prekey.key_id}")
        print(f"[CryptoManager] One-Time Pre-Keys: {len(self.one_time_prekeys)}")
        print("=" * 60)
    
    # =========================================================================
    # KEY GENERATION
    # =========================================================================
    
    def _generate_signed_prekey(self, key_id: int) -> SignedPreKey:
        """
        Generate a new Signed Pre-Key.
        
        The SPK is signed using our Identity Signing Key (Ed25519).
        Others verify this signature to ensure the SPK belongs to us.
        """
        import time
        key_pair = KeyPair.generate()
        
        # Sign the public key with our identity signing key
        signature = self.identity_signing_key.sign(key_pair.get_public_bytes())
        
        return SignedPreKey(
            key_id=key_id,
            key_pair=key_pair,
            signature=signature,
            timestamp=time.time()
        )
    
    def _generate_one_time_prekeys(self, count: int, start_id: int = 1) -> None:
        """
        Generate a batch of One-Time Pre-Keys.
        
        OPKs provide forward secrecy even if the SPK is compromised.
        Each OPK can only be used once and is deleted after use.
        """
        for i in range(count):
            key_id = start_id + i
            self.one_time_prekeys[key_id] = OneTimePreKey(
                key_id=key_id,
                key_pair=KeyPair.generate()
            )
    
    def get_prekey_bundle(self) -> PreKeyBundle:
        """
        Create a Pre-Key Bundle for publishing to the server.
        
        This bundle contains everything another user needs to 
        establish a session with us, even when we're offline.
        """
        # Get an unused OPK
        opk = None
        opk_id = None
        for kid, key in self.one_time_prekeys.items():
            if not key.used:
                opk = key.get_public_bytes()
                opk_id = kid
                break
        
        return PreKeyBundle(
            identity_key=self.identity_key.get_public_bytes(),
            identity_signing_key=self.identity_signing_key.get_public_bytes(),
            signed_prekey=self.signed_prekey.get_public_bytes(),
            signed_prekey_id=self.signed_prekey.key_id,
            signed_prekey_signature=self.signed_prekey.signature,
            one_time_prekey=opk,
            one_time_prekey_id=opk_id
        )
    
    def mark_opk_used(self, opk_id: int) -> None:
        """Mark a One-Time Pre-Key as used (should be deleted after use)."""
        if opk_id in self.one_time_prekeys:
            self.one_time_prekeys[opk_id].used = True
            print(f"[CryptoManager] OPK #{opk_id} marked as used")
    
    # =========================================================================
    # PUBLIC KEY EXPORT
    # =========================================================================
    
    def get_public_key_bytes(self) -> bytes:
        """Get identity public key as bytes."""
        return self.identity_key.get_public_bytes()
    
    def get_public_key_b64(self) -> str:
        """Get identity public key as base64."""
        return base64.b64encode(self.get_public_key_bytes()).decode('utf-8')
    
    def get_fingerprint(self, peer_public_key: Optional[bytes] = None) -> str:
        """
        Generate Safety Number for identity verification.
        
        If peer_public_key is provided, generates shared fingerprint.
        """
        if peer_public_key:
            return KeyFingerprint.generate(
                self.get_public_key_bytes(),
                peer_public_key
            )
        return KeyFingerprint.generate_short(self.get_public_key_bytes())
    
    def get_fingerprint_short(self) -> str:
        """Get short fingerprint for display."""
        return KeyFingerprint.generate_short(self.get_public_key_bytes())
    
    def get_identity_key_b64(self) -> str:
        """Get identity public key as base64 (alias for get_public_key_b64)."""
        return self.get_public_key_b64()
    
    def get_prekey_bundle_for_server(self) -> Dict[str, Any]:
        """
        Get Pre-Key Bundle in server-friendly format for upload.
        
        Returns a dictionary suitable for JSON serialization and server storage.
        """
        bundle = self.get_prekey_bundle()
        
        # Get all unused OPKs (not just one)
        opks = []
        for key_id, opk in self.one_time_prekeys.items():
            if not opk.used:
                opks.append({
                    'key_id': key_id,
                    'public_key': base64.b64encode(opk.get_public_bytes()).decode('utf-8')
                })
                # Limit to a reasonable number
                if len(opks) >= 10:
                    break
        
        return {
            'identity_key': base64.b64encode(bundle.identity_key).decode('utf-8'),
            'identity_signing_key': base64.b64encode(bundle.identity_signing_key).decode('utf-8'),
            'signed_prekey': base64.b64encode(bundle.signed_prekey).decode('utf-8'),
            'signed_prekey_id': bundle.signed_prekey_id,
            'signed_prekey_signature': base64.b64encode(bundle.signed_prekey_signature).decode('utf-8'),
            'one_time_prekeys': opks
        }
    
    def import_prekey_bundle(self, peer_username: str, bundle_dict: Dict[str, Any]) -> bool:
        """
        Import a Pre-Key Bundle from server format and establish session.
        
        Args:
            peer_username: The peer's username
            bundle_dict: Bundle dictionary from server
            
        Returns:
            True if session established successfully
        """
        try:
            # Parse bundle from server format
            identity_key = base64.b64decode(bundle_dict['identity_key'])
            identity_signing_key = base64.b64decode(bundle_dict['identity_signing_key'])
            signed_prekey = base64.b64decode(bundle_dict['signed_prekey'])
            signed_prekey_id = bundle_dict['signed_prekey_id']
            signed_prekey_signature = base64.b64decode(bundle_dict['signed_prekey_signature'])
            
            # Get one OPK if available
            opk = None
            opk_id = None
            opks = bundle_dict.get('one_time_prekeys', [])
            if opks and len(opks) > 0:
                opk_data = opks[0]
                opk = base64.b64decode(opk_data['public_key'])
                opk_id = opk_data['key_id']
            
            # Create PreKeyBundle object
            bundle = PreKeyBundle(
                identity_key=identity_key,
                identity_signing_key=identity_signing_key,
                signed_prekey=signed_prekey,
                signed_prekey_id=signed_prekey_id,
                signed_prekey_signature=signed_prekey_signature,
                one_time_prekey=opk,
                one_time_prekey_id=opk_id
            )
            
            # Import and establish session
            return self.import_peer_bundle(peer_username, bundle)
            
        except Exception as e:
            print(f"[CryptoManager] Failed to import pre-key bundle: {e}")
            import traceback
            traceback.print_exc()
            return False
    
    def get_key_fingerprint(self, peer_username: str) -> Optional[str]:
        """
        Get Safety Number (key fingerprint) for a peer.
        
        This is used for out-of-band identity verification.
        
        Args:
            peer_username: The peer's username
            
        Returns:
            Safety number string or None if peer unknown
        """
        if peer_username in self.peer_public_keys:
            return self.get_fingerprint(self.peer_public_keys[peer_username])
        elif peer_username in self.peer_bundles:
            return self.get_fingerprint(self.peer_bundles[peer_username].identity_key)
        return None
    
    @property
    def ratchet_sessions(self) -> Dict[str, 'DoubleRatchet']:
        """Alias for sessions property for client compatibility."""
        return self.sessions
    
    # =========================================================================
    # SESSION ESTABLISHMENT (X3DH)
    # =========================================================================
    
    def import_peer_bundle(self, peer_username: str, bundle: PreKeyBundle) -> bool:
        """
        Import a peer's pre-key bundle and establish a session.
        
        This performs the X3DH key agreement as the initiator.
        """
        try:
            # Generate ephemeral key for this session
            ephemeral_key = KeyPair.generate()
            
            # Perform X3DH
            shared_secret, _ = X3DHKeyAgreement.perform_key_agreement_initiator(
                my_identity_key=self.identity_key,
                my_ephemeral_key=ephemeral_key,
                peer_bundle=bundle
            )
            
            # Store bundle and ephemeral key for session
            self.peer_bundles[peer_username] = bundle
            
            # Initialize Double Ratchet as Alice (initiator)
            ratchet = DoubleRatchet()
            ratchet.initialize_as_alice(shared_secret, bundle.signed_prekey)
            
            # Store ephemeral key for X3DH header in first message
            ratchet.x3dh_ephemeral_key = ephemeral_key.get_public_bytes()
            ratchet.x3dh_identity_key = self.identity_key.get_public_bytes()
            ratchet.x3dh_used_opk_id = bundle.one_time_prekey_id
            ratchet.is_first_message = True  # Flag to include X3DH header
            
            self.sessions[peer_username] = ratchet
            
            # Also store for legacy compatibility
            self.peer_public_keys[peer_username] = bundle.identity_key
            
            print(f"[CryptoManager] ✓ Session established with '{peer_username}' via X3DH")
            print(f"[CryptoManager] Safety Number: {self.get_fingerprint(bundle.identity_key)[:30]}...")
            
            return True
            
        except Exception as e:
            print(f"[CryptoManager] Failed to establish session with '{peer_username}': {e}")
            import traceback
            traceback.print_exc()
            return False
    
    def import_peer_public_key(self, username: str, public_key_bytes: bytes) -> bool:
        """
        Legacy import - just store public key for simplified encryption.
        For full protocol, use import_peer_bundle instead.
        """
        try:
            self.peer_public_keys[username] = public_key_bytes
            # Invalidate session key cache
            if username in self._session_key_cache:
                del self._session_key_cache[username]
            print(f"[CryptoManager] Imported public key for '{username}'")
            return True
        except Exception as e:
            print(f"[CryptoManager] Failed to import key: {e}")
            return False
    
    def import_peer_public_key_b64(self, username: str, public_key_b64: str) -> bool:
        """Import peer's public key from base64."""
        try:
            public_key_bytes = base64.b64decode(public_key_b64)
            return self.import_peer_public_key(username, public_key_bytes)
        except Exception as e:
            print(f"[CryptoManager] Failed to decode key: {e}")
            return False
    
    # =========================================================================
    # MESSAGE ENCRYPTION (Double Ratchet)
    # =========================================================================
    
    def encrypt_message(self, message: str, sender_username: str) -> Optional[Dict[str, Any]]:
        """
        Encrypt a message using Double Ratchet (or fallback to simple encryption).
        
        If a full session exists (established via X3DH), uses Double Ratchet.
        Otherwise, falls back to simplified Sender Key approach.
        """
        if not self.peer_public_keys and not self.sessions:
            print("[CryptoManager] No peers available")
            return None
        
        # Check if we have full sessions
        if self.sessions:
            return self._encrypt_with_double_ratchet(message, sender_username)
        else:
            return self._encrypt_with_sender_key(message, sender_username)
    
    def _encrypt_with_double_ratchet(self, message: str, sender_username: str) -> Dict[str, Any]:
        """
        Encrypt using Double Ratchet for full forward secrecy.
        """
        encrypted_messages = {}
        x3dh_headers = {}  # X3DH headers for initial messages
        
        for peer_username, ratchet in self.sessions.items():
            # Encrypt message with this peer's ratchet
            ratchet_message = ratchet.encrypt(message.encode('utf-8'))
            encrypted_messages[peer_username] = ratchet_message
            
            # Include X3DH header for first message (so responder can derive shared secret)
            if hasattr(ratchet, 'is_first_message') and ratchet.is_first_message:
                x3dh_headers[peer_username] = {
                    'identity_key': base64.b64encode(ratchet.x3dh_identity_key).decode(),
                    'ephemeral_key': base64.b64encode(ratchet.x3dh_ephemeral_key).decode(),
                    'used_opk_id': ratchet.x3dh_used_opk_id
                }
                ratchet.is_first_message = False  # Clear flag after first message
        
        payload = {
            'type': 'E2EE_MESSAGE',
            'version': SignalConstants.PROTOCOL_VERSION,
            'protocol': 'DOUBLE_RATCHET',
            'sender': sender_username,
            'sender_public_key': self.get_public_key_b64(),
            'sender_bundle': self.get_prekey_bundle().to_dict(),
            'messages': encrypted_messages
        }
        
        # Add X3DH headers if present
        if x3dh_headers:
            payload['x3dh_headers'] = x3dh_headers
        
        print(f"[CryptoManager] ✓ Encrypted with Double Ratchet for {len(encrypted_messages)} peer(s)")
        return payload
    
    def _encrypt_with_sender_key(self, message: str, sender_username: str) -> Dict[str, Any]:
        """
        Fallback: Encrypt using simplified Sender Key approach.
        """
        # Generate random message key
        message_key = os.urandom(SignalConstants.AES_KEY_SIZE)
        
        # Encrypt message
        nonce = os.urandom(SignalConstants.NONCE_SIZE)
        aesgcm = AESGCM(message_key)
        ciphertext = aesgcm.encrypt(nonce, message.encode('utf-8'), None)
        
        # Encrypt message key for each peer
        encrypted_keys = {}
        for peer_username, peer_key_bytes in self.peer_public_keys.items():
            # Derive session key
            peer_key = x25519.X25519PublicKey.from_public_bytes(peer_key_bytes)
            shared_secret = self.identity_key.private_key.exchange(peer_key)
            
            hkdf = HKDF(
                algorithm=hashes.SHA256(),
                length=SignalConstants.AES_KEY_SIZE,
                salt=None,
                info=SignalConstants.HKDF_INFO_X3DH,
                backend=default_backend()
            )
            session_key = hkdf.derive(shared_secret)
            
            # Encrypt message key
            key_nonce = os.urandom(SignalConstants.NONCE_SIZE)
            key_aesgcm = AESGCM(session_key)
            encrypted_mk = key_aesgcm.encrypt(key_nonce, message_key, None)
            
            encrypted_keys[peer_username] = {
                'nonce': base64.b64encode(key_nonce).decode(),
                'encrypted_key': base64.b64encode(encrypted_mk).decode()
            }
        
        payload = {
            'type': 'E2EE_MESSAGE',
            'version': SignalConstants.PROTOCOL_VERSION,
            'protocol': 'SENDER_KEY',
            'sender': sender_username,
            'sender_public_key': self.get_public_key_b64(),
            'iv': base64.b64encode(nonce).decode(),
            'ciphertext': base64.b64encode(ciphertext).decode(),
            'keys': encrypted_keys
        }
        
        print(f"[CryptoManager] ✓ Encrypted with Sender Key for {len(encrypted_keys)} peer(s)")
        return payload
    
    # =========================================================================
    # MESSAGE DECRYPTION
    # =========================================================================
    
    def decrypt_message(self, payload: Dict[str, Any]) -> Optional[str]:
        """
        Decrypt a message using appropriate protocol.
        """
        if payload.get('type') != 'E2EE_MESSAGE':
            return None
        
        protocol = payload.get('protocol', 'SENDER_KEY')
        sender = payload.get('sender')
        
        # Import sender's public key for legacy/fallback mode
        if sender and payload.get('sender_public_key'):
            if sender not in self.peer_public_keys:
                self.import_peer_public_key_b64(sender, payload['sender_public_key'])
        
        # NOTE: For Double Ratchet, do NOT call import_peer_bundle here!
        # The session should be established in _decrypt_with_double_ratchet 
        # using the X3DH header from the message (as responder).
        # import_peer_bundle would establish us as initiator with wrong keys.
        
        if protocol == 'DOUBLE_RATCHET':
            return self._decrypt_with_double_ratchet(payload, sender)
        else:
            return self._decrypt_with_sender_key(payload, sender)
    
    def _decrypt_with_double_ratchet(self, payload: Dict[str, Any], sender: str) -> Optional[str]:
        """Decrypt using Double Ratchet."""
        try:
            messages = payload.get('messages', {})
            if self.username not in messages:
                print(f"[CryptoManager] No message for us in Double Ratchet payload")
                return None
            
            ratchet_message = messages[self.username]
            x3dh_headers = payload.get('x3dh_headers', {})
            
            # Get or create session
            if sender not in self.sessions:
                # Initialize as Bob (responder)
                print(f"[CryptoManager] Creating new session as responder for '{sender}'")
                
                # Get X3DH header for this recipient
                x3dh_header = x3dh_headers.get(self.username, {})
                
                if x3dh_header:
                    # Use X3DH header from the message
                    peer_identity_key = base64.b64decode(x3dh_header['identity_key'])
                    peer_ephemeral_key = base64.b64decode(x3dh_header['ephemeral_key'])
                    used_opk_id = x3dh_header.get('used_opk_id')
                    
                    # Get the OPK that was used (if any)
                    my_one_time_prekey = None
                    if used_opk_id and used_opk_id in self.one_time_prekeys:
                        my_one_time_prekey = self.one_time_prekeys[used_opk_id]
                        print(f"[CryptoManager] Using One-Time Pre-Key #{used_opk_id}")
                    
                    shared_secret, _ = X3DHKeyAgreement.perform_key_agreement_responder(
                        my_identity_key=self.identity_key,
                        my_signed_prekey=self.signed_prekey,
                        my_one_time_prekey=my_one_time_prekey,
                        peer_identity_key=peer_identity_key,
                        peer_ephemeral_key=peer_ephemeral_key
                    )
                    
                    # Mark OPK as used
                    if used_opk_id:
                        self.mark_opk_used(used_opk_id)
                    
                    # Initialize Double Ratchet as Bob
                    ratchet = DoubleRatchet()
                    ratchet.initialize_as_bob(shared_secret, self.signed_prekey.key_pair)
                    self.sessions[sender] = ratchet
                    
                    # Store peer's identity key
                    self.peer_public_keys[sender] = peer_identity_key
                    
                    print(f"[CryptoManager] ✓ Session established with '{sender}' as responder")
                else:
                    print(f"[CryptoManager] No X3DH header found for initial message!")
                    return None
            
            if sender in self.sessions:
                plaintext_bytes = self.sessions[sender].decrypt(ratchet_message)
                return plaintext_bytes.decode('utf-8')
            
            return None
            
        except Exception as e:
            print(f"[CryptoManager] Double Ratchet decryption failed: {e}")
            import traceback
            traceback.print_exc()
            return None
    
    def _decrypt_with_sender_key(self, payload: Dict[str, Any], sender: str) -> Optional[str]:
        """Decrypt using Sender Key approach."""
        try:
            encrypted_keys = payload.get('keys', {})
            if self.username not in encrypted_keys:
                print(f"[CryptoManager] No key for us in payload")
                return None
            
            # Get sender's public key
            sender_key_bytes = self.peer_public_keys.get(sender)
            if not sender_key_bytes:
                print(f"[CryptoManager] Unknown sender: {sender}")
                return None
            
            sender_key = x25519.X25519PublicKey.from_public_bytes(sender_key_bytes)
            
            # Derive session key
            shared_secret = self.identity_key.private_key.exchange(sender_key)
            hkdf = HKDF(
                algorithm=hashes.SHA256(),
                length=SignalConstants.AES_KEY_SIZE,
                salt=None,
                info=SignalConstants.HKDF_INFO_X3DH,
                backend=default_backend()
            )
            session_key = hkdf.derive(shared_secret)
            
            # Decrypt message key
            our_key_data = encrypted_keys[self.username]
            key_nonce = base64.b64decode(our_key_data['nonce'])
            encrypted_mk = base64.b64decode(our_key_data['encrypted_key'])
            
            aesgcm = AESGCM(session_key)
            message_key = aesgcm.decrypt(key_nonce, encrypted_mk, None)
            
            # Decrypt message
            msg_nonce = base64.b64decode(payload['iv'])
            ciphertext = base64.b64decode(payload['ciphertext'])
            
            msg_aesgcm = AESGCM(message_key)
            plaintext = msg_aesgcm.decrypt(msg_nonce, ciphertext, None)
            
            print(f"[CryptoManager] ✓ Decrypted message from '{sender}'")
            return plaintext.decode('utf-8')
            
        except Exception as e:
            print(f"[CryptoManager] Sender Key decryption failed: {e}")
            import traceback
            traceback.print_exc()
            return None
    
    # =========================================================================
    # UTILITY METHODS
    # =========================================================================
    
    def serialize_payload(self, payload: Dict[str, Any]) -> str:
        """Serialize payload to JSON."""
        return json.dumps(payload)
    
    @staticmethod
    def deserialize_payload(json_str: str) -> Optional[Dict[str, Any]]:
        """Deserialize JSON to payload."""
        try:
            payload = json.loads(json_str)
            if isinstance(payload, dict) and payload.get('type') == 'E2EE_MESSAGE':
                return payload
            return None
        except:
            return None
    
    def get_encryption_debug_info(self, payload: Dict[str, Any]) -> str:
        """Generate debug info for demonstration."""
        protocol = payload.get('protocol', 'SENDER_KEY')
        
        lines = [
            "=" * 70,
            "🔐 COMPLETE SIGNAL PROTOCOL - ENCRYPTION DEBUG",
            "=" * 70,
            f"Protocol: {protocol}",
            f"Version: {payload.get('version')}",
            f"Sender: {payload.get('sender')}",
            "",
        ]
        
        if protocol == 'DOUBLE_RATCHET':
            lines.extend([
                "[ Double Ratchet Encryption ]",
                "  ✓ Perfect Forward Secrecy (each message has unique key)",
                "  ✓ Break-in Recovery (session heals after compromise)",
                "  ✓ DH Ratchet + Symmetric Ratchet combined",
                "",
                "[ Encrypted Messages ]"
            ])
            for peer, msg in payload.get('messages', {}).items():
                lines.append(f"  → {peer}:")
                lines.append(f"      DH Public: {msg['header']['dh_public'][:32]}...")
                lines.append(f"      Msg #: {msg['header']['message_number']}")
                lines.append(f"      Ciphertext: {msg['ciphertext'][:32]}...")
        else:
            lines.extend([
                "[ Sender Key Encryption (AES-256-GCM) ]",
                f"  IV/Nonce: {payload.get('iv', 'N/A')}",
                f"  Ciphertext: {payload.get('ciphertext', '')[:40]}...",
                "",
                "[ Per-Recipient Encrypted Keys (ECDH + HKDF) ]"
            ])
            for peer, key_data in payload.get('keys', {}).items():
                lines.append(f"  → {peer}:")
                lines.append(f"      Nonce: {key_data['nonce']}")
                lines.append(f"      Encrypted MK: {key_data['encrypted_key'][:24]}...")
        
        lines.extend([
            "",
            "🔒 Server sees ONLY ciphertext - CANNOT decrypt!",
            "=" * 70
        ])
        
        return "\n".join(lines)
    
    def get_session_info(self) -> str:
        """Get information about active sessions."""
        lines = [
            "=" * 50,
            "Active Sessions",
            "=" * 50
        ]
        
        for peer, ratchet in self.sessions.items():
            state = ratchet.state
            lines.append(f"\n{peer}:")
            lines.append(f"  Sent: {state.sending_message_number} messages")
            lines.append(f"  Received: {state.receiving_message_number} messages")
            lines.append(f"  Root Key: {state.root_key.hex()[:16] if state.root_key else 'None'}...")
        
        if not self.sessions:
            lines.append("\nNo active Double Ratchet sessions")
            lines.append(f"Simple key exchanges: {len(self.peer_public_keys)}")
        
        return "\n".join(lines)


# ============================================================================
# EXAMPLE AND TESTING
# ============================================================================

if __name__ == "__main__":
    print("=" * 70)
    print("COMPLETE SIGNAL PROTOCOL DEMO")
    print("=" * 70)
    
    # Create two users
    print("\n[1] Creating Alice and Bob...")
    alice = CryptoManager("Alice")
    bob = CryptoManager("Bob")
    
    # Exchange pre-key bundles (simulating server distribution)
    print("\n[2] Exchanging Pre-Key Bundles (X3DH)...")
    alice_bundle = alice.get_prekey_bundle()
    bob_bundle = bob.get_prekey_bundle()
    
    # Alice establishes session with Bob
    alice.import_peer_bundle("Bob", bob_bundle)
    
    # Verify safety numbers match
    print("\n[3] Safety Number Verification...")
    alice_safety = alice.get_fingerprint(bob.get_public_key_bytes())
    bob_safety = bob.get_fingerprint(alice.get_public_key_bytes())
    print(f"Alice sees: {alice_safety[:30]}...")
    print(f"Bob sees:   {bob_safety[:30]}...")
    print(f"Match: {alice_safety == bob_safety}")
    
    # Alice sends first message
    print("\n[4] Alice sends encrypted message...")
    original = "Hello Bob! This is a secret message using full Signal Protocol! 🔐"
    encrypted = alice.encrypt_message(original, "Alice")
    
    if encrypted:
        print(alice.get_encryption_debug_info(encrypted))
        
        # Bob receives and decrypts
        print("\n[5] Bob decrypts message...")
        decrypted = bob.decrypt_message(encrypted)
        
        print(f"\nOriginal:  {original}")
        print(f"Decrypted: {decrypted}")
        print(f"Match: {original == decrypted}")
        
        # Show session state
        print(alice.get_session_info())
