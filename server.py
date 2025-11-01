import asyncio
import json
import logging
import websockets
from websockets.exceptions import ConnectionClosedOK, ConnectionClosedError

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes

# --- Configuration ---
HOST = "localhost"
PORT = 8765
logging.basicConfig(level=logging.INFO)

# --- Server Key Management ---
# The server uses a single, session-wide AES key for all communication.
# Clients must use this key to encrypt/decrypt messages.
import os
import binascii
KEY_SIZE = 32 # 256 bits for AES-256
SERVER_KEY_RAW = os.urandom(KEY_SIZE)
SERVER_KEY_HEX = binascii.hexlify(SERVER_KEY_RAW).decode('utf-8')

print("----------------------------------------------------------------------")
print(f"Server Key (Paste this into the browser): {SERVER_KEY_HEX}")
print("----------------------------------------------------------------------")

# Global dictionary to map WebSocket objects to client IDs
USERS = {}
# Counter for sequential ID assignment
USER_COUNTER = 0

# --- Cryptography Functions (Server-Side) ---

def decrypt_data(data: bytes) -> bytes:
    """
    Decrypts data (nonce + ciphertext + tag) using the server key.
    
    The GCM tag is passed directly into the modes.GCM constructor for robust compatibility.
    """
    # Minimum size: 12 (nonce) + 16 (tag) = 28 bytes
    if len(data) < 28: 
        raise ValueError("Encrypted data too short for AES-GCM (requires 12-byte nonce + 16-byte tag minimum).")
    
    nonce = data[:12]
    tag = data[-16:] 
    ciphertext = data[12:-16]
    
    # 1. Initialize GCM mode with BOTH nonce and the extracted tag
    cipher = Cipher(algorithms.AES(SERVER_KEY_RAW), modes.GCM(nonce, tag), backend=default_backend())
    decryptor = cipher.decryptor()
    
    # 2. Decrypt ONLY the ciphertext
    plaintext = decryptor.update(ciphertext) + decryptor.finalize()
    return plaintext

def encrypt_data(data: bytes) -> bytes:
    """Encrypts plaintext data using the server key, returning (nonce + ciphertext + tag)."""
    nonce = os.urandom(12) # GCM recommends a 12-byte nonce (IV)
    
    cipher = Cipher(algorithms.AES(SERVER_KEY_RAW), modes.GCM(nonce), backend=default_backend())
    encryptor = cipher.encryptor()
    
    ciphertext = encryptor.update(data) + encryptor.finalize()
    
    # Python returns nonce + ciphertext + tag
    return nonce + ciphertext + encryptor.tag

# --- Framing Functions ---

def frame_data(data: bytes) -> bytes:
    """Adds a 4-byte Big-Endian length prefix to the data."""
    length = len(data)
    # Pack the length into 4 bytes (Big Endian)
    header = length.to_bytes(4, 'big')
    return header + data

def unframe_data(framed_data: bytes) -> bytes:
    """Removes the 4-byte length prefix and verifies length."""
    if len(framed_data) < 4:
        raise ValueError("Framed data too short.")
    
    # Unpack the length from 4 bytes (Big Endian)
    length = int.from_bytes(framed_data[:4], 'big')
    data = framed_data[4:]
    
    if len(data) != length:
        # This is a critical check for ensuring integrity of the message
        raise ValueError(f"Length mismatch: Expected {length} bytes, got {len(data)} bytes.")
        
    return data

# --- WebSocket Handlers ---

async def send_control_message(websocket, message_json):
    """Encrypts and sends a control message (like INIT) to a single client."""
    try:
        message_bytes = json.dumps(message_json).encode('utf-8')
        encrypted_message = encrypt_data(message_bytes)
        framed_message = frame_data(encrypted_message)
        await websocket.send(framed_message)
    except Exception as e:
        logging.error(f"Failed to send control message to {websocket.remote_address}: {e}")

async def register(websocket):
    """Registers a client, assigns a sequential ID, and sends the ID back."""
    global USER_COUNTER
    USER_COUNTER += 1
    user_id = f"Client {USER_COUNTER}"
    USERS[websocket] = user_id
    logging.info(f"[{websocket.remote_address}] Registered as {user_id}. Total users: {len(USERS)}")
    
    # Send the assigned ID back to the client
    await send_control_message(websocket, {"type": "init", "userId": user_id})

async def unregister(websocket):
    """Unregisters a client."""
    user_id = USERS.pop(websocket, "Unknown Client")
    logging.info(f"[{websocket.remote_address}] Unregistered {user_id}. Total users: {len(USERS)}")

async def broadcast(message_bytes: bytes, sender_websocket):
    """
    Sends the raw JSON plaintext message (now including senderId) to all clients except the sender.
    The message must be re-encrypted for broadcast.
    """
    # Re-encrypt the message once for broadcast
    try:
        encrypted_message = encrypt_data(message_bytes)
        framed_message = frame_data(encrypted_message)
    except Exception as e:
        logging.error(f"Error re-encrypting message for broadcast: {e}")
        return

    # Create a set of recipients (all users except the sender)
    recipients = USERS.keys() - {sender_websocket}

    if not recipients:
        logging.info("No other clients to broadcast to.")
        return

    successful_sends = 0
    # Send the message to all recipients using a safe loop
    for ws in recipients:
        try:
            await ws.send(framed_message)
            successful_sends += 1
        except (ConnectionClosedOK, ConnectionClosedError) as e:
            # Client disconnected right before the send attempt, gracefully ignore
            logging.warning(f"Could not send to {ws.remote_address}: connection closed.")
        except Exception as e:
            # Other errors
            logging.error(f"Unexpected error sending to {ws.remote_address}: {e}")

    logging.info(f"Broadcasted message successfully to {successful_sends} out of {len(recipients)} clients.")

async def ws_handler(websocket):
    """Handles connection, message processing, and disconnection."""
    await register(websocket)
    sender_id = USERS.get(websocket, "Unknown Client")

    try:
        async for framed_encrypted_data in websocket:
            try:
                # 1. Unframe the data
                encrypted_data = unframe_data(framed_encrypted_data)
                
                # 2. Decrypt the message
                plaintext_bytes = decrypt_data(encrypted_data)
                plaintext_str = plaintext_bytes.decode('utf-8')

                # 3. Parse JSON, log, and prepare for broadcast
                try:
                    message_json = json.loads(plaintext_str)
                    
                    if message_json.get("type") == "msg" and "text" in message_json:
                        chat_text = message_json["text"]
                        
                        # --- NEW LOG FORMAT ---
                        logging.info(f"[{sender_id}]: {chat_text}")
                        
                        # Add sender ID to the message before re-encrypting and broadcasting
                        message_json["senderId"] = sender_id
                        # Re-encode the modified JSON back to bytes
                        broadcast_bytes = json.dumps(message_json).encode('utf-8')
                        
                        # 4. Broadcast the updated message
                        await broadcast(broadcast_bytes, websocket)
                    elif message_json.get("type") == "ping":
                        # Log ping requests without broadcasting the text
                        logging.info(f"[{sender_id}]: PING")
                    else:
                        # Handle other types of messages or unknown structure
                        logging.info(f"[{sender_id}] Received non-chat message or unknown type: {plaintext_str}")
                        
                except json.JSONDecodeError:
                    logging.error(f"[{sender_id}] Received non-JSON or invalid JSON payload: {plaintext_str}")
                
            except websockets.exceptions.ConnectionClosedOK:
                break
            except (ConnectionClosedError, ConnectionResetError):
                break
            except Exception as e:
                logging.error(f"[{sender_id}] Message processing error: {e}")
                pass
                
    finally:
        await unregister(websocket)

# --- Main Execution ---

async def main():
    """Starts the WebSocket server."""
    async with websockets.serve(ws_handler, HOST, PORT):
        logging.info(f"Server started on ws://{HOST}:{PORT}")
        await asyncio.Future() # run forever

if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        print("\nServer shutting down.")
    except Exception as e:
        logging.error(f"An unexpected error occurred: {e}")
