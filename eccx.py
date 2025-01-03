"""
\n▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄
\n█▄─▄▄─█─▄▄▄─█─▄▄▄─█▄─▀─▄█
\n██─▄█▀█─███▀█─███▀██▀─▀██
\n█▄▄▄▄▄█▄▄▄▄▄█▄▄▄▄▄█▄▄█▄▄█

## author: @gamerjamer43 on github, @microwavedpopcorn on discord
### hi there! this is an elliptic curve encrypted solution to encrypting, decrypting, signing, and verifiying messages.
### modeled after the way pgp works and attempting to use the elliptic curve system instead, which is both faster than AES (which it still uses to encrypt) and more secure than RSA.

## classes:
ECKeyManager: key manager class for the program. manages the creation, saving, and loading of elliptic curve keys.
ECSignature: signature class to handle the signing and verifying of messages.
ECHybridEncryption: class to handle ECHE, combining ECDH for key exchange and AES for encryption.
"""

# lotta fucking imports. disgusting.
from cryptography.hazmat.primitives import hashes, serialization, padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.backends import default_backend
from cryptography.exceptions import InvalidSignature

# the less ugly shit
from rich.prompt import Prompt
from rich import print
import base64, os

# your paths for storing keys, these are default to the folder
PRIVATE_KEY_FILE = "private_key.pem"
PUBLIC_KEY_FILE = "public_key.pem"
SIGNED_KEY_FILE = "signed_public_key.pem"

# the actual manager
class ECKeyManager:
    """### key manager class for the program. manages the creation, saving, and loading of elliptic curve keys.

    methods:
    - ECKeyManager.generate_and_save_keys() -> generate and save keys for the user
    - ECKeyManager.load_private_key() -> load and return the private key from the saved file, creating a new one if necessary.
    - ECKeyManager.load_public_key() -> load and return the public key from the saved file, creating a new one if necessary.
    - ECKeyManager.sign_public_key(public_key, private_key) -> use the loaded keys to sign the public key with the private key and save the signature."""

    def __init__(self, private_key_file=PRIVATE_KEY_FILE, public_key_file=PUBLIC_KEY_FILE):
        """### initialize the manager class with paths for the private and public keys.

        args:
            private_key_file (str): path to private key file.
            public_key_file (str): path to public key file.
        """
        self.private_key_file = private_key_file
        self.public_key_file = public_key_file

    def generate_and_save_keys(self):
        """### generate and save a key pair.
        
        generates a new private-public key pair using the SECP256R1 curve and saves them in .PEM files."""
        
        private_key = ec.generate_private_key(ec.SECP256R1(), backend=default_backend())

        with open(self.private_key_file, "wb") as f:
            f.write(private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption(),
            ))
        
        public_key = private_key.public_key()
        with open(self.public_key_file, "wb") as f:
            f.write(public_key.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo,
            ))

        print("[bold green]Keys generated and saved successfully.[/bold green]")

    def load_private_key(self):
        """### load and return the private key from the file.

        returns:
            private_key (EllipticCurvePrivateKey): the loaded private key object.
        """

        if not os.path.exists(self.private_key_file):
            print("[bold red]Private key not found. Generating a new key pair.[/bold red]")
            self.generate_and_save_keys()

        with open(self.private_key_file, "rb") as f:
            return serialization.load_pem_private_key(f.read(), password=None, backend=default_backend())

    def load_public_key(self):
        """### load and return the public key from a file.
        returns:
            public_key (EllipticCurvePublicKey): the loaded public key object."""
        
        if not os.path.exists(self.public_key_file):
            print("[bold red]Public key not found. Generating a new key pair.[/bold red]")
            self.generate_and_save_keys()

        with open(self.public_key_file, "rb") as f:
            return serialization.load_pem_public_key(f.read(), backend=default_backend())

    def sign_public_key(self, public_key, private_key):
        """### signs the given public key using the provided private key, and saves the signed public key
        along with the signature to the specified file.

        args:
            public_key (EllipticCurvePublicKey): the public key to be signed.
            private_key (EllipticCurvePrivateKey): the private key used to sign the public key."""
        
        signature = private_key.sign(
            public_key.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            ),
            ec.ECDSA(hashes.SHA256())
        )
        with open(SIGNED_KEY_FILE, "wb") as f:
            f.write(public_key.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            ) + b"\n" + signature)
        print(f"[bold green]Public key signed and saved to {SIGNED_KEY_FILE}[/bold green]")


class ECSignature:
    """### signature class to handle the signing and verifying of messages.

    this class provides methods for signing messages with a private key and verifying the validity of
    a signature using the corresponding public key. The signing algorithm used is ECDSA with the SHA256 hash function.
    
    methods:
    - ECSignature.sign_message(private_key, message) -> sign a message using the provided private key.
    - ECSignature.verify_signature(public_key, message, signature) -> verify the signature of a message using the public key.
    """

    @staticmethod
    def sign_message(private_key, message: str):
        """### sign a message using the private key.
            
        this signs the message using the ECDSA algorithm with SHA256.

        args:
            private_key (EllipticCurvePrivateKey): the private key used to sign the message.
            message (str): the message to be signed.

        returns:
            str: the hex representation of the signature."""
        
        signature = private_key.sign(
            message.encode(),
            ec.ECDSA(hashes.SHA256())
        )
        return signature.hex()

    @staticmethod
    def verify_signature(public_key, message: str, signature: str):
        """### verify the signature of a message using the sender's public key.

        checks the validity of the given signature for a message using the corresponding public key.

        args:
            public_key (EllipticCurvePublicKey): the public key used to verify the signature.
            message (str): the message to be verified.
            signature (str): the signature in hex format.

        returns:
            bool: True if the signature is valid, False if invalid.
        """
        try:
            public_key.verify(
                bytes.fromhex(signature),
                message.encode(),
                ec.ECDSA(hashes.SHA256())
            )
            return True
        except InvalidSignature:
            return False


class ECHybridEncryption:
    """class to handle ECHE, combining ECDH for key exchange and AES for encryption.
    
    Methods:
    - ECHybridEncryption.generate_shared_secret(private_key, public_key, salt) -> derive a shared secret using ECDH and PBKDF2.
    - ECHybridEncryption.encrypt_message(public_key, message, private_key) -> encrypt a message using hybrid encryption (ECDH + AES).
    - ECHybridEncryption.decrypt_message(private_key, encrypted_message, public_key) -> decrypt a message using hybrid encryption (ECDH + AES).
    """
    @staticmethod
    def generate_shared_secret(private_key, public_key, salt):
        """generate a shared secret using ECDH and derive a symmetric key.

        Args:
            private_key (EllipticCurvePrivateKey): the private key for the local party.
            public_key (EllipticCurvePublicKey): the public key of the remote party.
            salt (bytes): a random salt used in the key derivation process.

        returns:
            bytes: the derived symmetric key used for AES encryption/decryption. convert this to a string and chop off the b'[text]' at the start and end of text
        """
        shared_secret = private_key.exchange(ec.ECDH(), public_key)

        # derive a symmetric key using PBKDF2 HMAC
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=100000,
            backend=default_backend()
        )
        symmetric_key = kdf.derive(shared_secret)
        return symmetric_key

    @staticmethod
    def encrypt_message(public_key, message: str, private_key):
        """encrypt a message using hybrid encryption (ECDH + AES).

        args:
            public_key (EllipticCurvePublicKey): the public key of the recipient for ECDH key exchange.
            message (str): the message to be encrypted.
            private_key (EllipticCurvePrivateKey): the private key of the sender for ECDH key exchange.

        returns:
            str: the encrypted message, encoded in base64 format (including salt and IV).
        """
        salt = os.urandom(16)
        symmetric_key = ECHybridEncryption.generate_shared_secret(private_key, public_key, salt)

        # pad the text
        iv = os.urandom(16)
        padder = padding.PKCS7(128).padder()
        padded_data = padder.update(message.encode()) + padder.finalize()

        # cypher bullshit, create an aes cipher and pad it using the data above, it's obvious what the last line does
        cipher = Cipher(algorithms.AES(symmetric_key), modes.CBC(iv), backend=default_backend())
        encryptor = cipher.encryptor()
        ciphertext = encryptor.update(padded_data) + encryptor.finalize()

        return base64.b64encode(salt + iv + ciphertext)

    @staticmethod
    def decrypt_message(private_key, encrypted_message: str, public_key):
        """decrypt a message using hybrid encryption (ECDH + AES).

        args:
            private_key (EllipticCurvePrivateKey): the private key of the recipient for ECDH key exchange.
            encrypted_message (str): the encrypted message in base64 format (including salt and IV).
            public_key (EllipticCurvePublicKey): the public key of the sender for ECDH key exchange.

        returns:
            str: the decrypted and original message.
        """
        encrypted_message = base64.b64decode(encrypted_message)

        salt = encrypted_message[:16]
        iv = encrypted_message[16:32]
        ciphertext = encrypted_message[32:]

        # now we have to do the reverse of the above shit
        symmetric_key = ECHybridEncryption.generate_shared_secret(private_key, public_key, salt)

        # reverse the cypher using its key, decrypt the message
        cipher = Cipher(algorithms.AES(symmetric_key), modes.CBC(iv), backend=default_backend())
        decryptor = cipher.decryptor()
        decrypted_data = decryptor.update(ciphertext) + decryptor.finalize()

        unpadder = padding.PKCS7(128).unpadder()
        original_message = unpadder.update(decrypted_data) + unpadder.finalize()

        return original_message.decode()

def cli():
    key_manager = ECKeyManager()

    private_key = key_manager.load_private_key()
    public_key = key_manager.load_public_key()

    os.system("cls")
    while True:
        print("\n[bold cyan]--- EC Encryption CLI ---[/bold cyan]\n")
        print("1. Sign or verify a message")
        print("2. Encrypt and decrypt a message")
        print("3. Exit")

        choice = Prompt.ask("[bold blue]Choose an option: [/bold blue]")
        
        # big bertha. king ugly. ugly betty. whatever you wanna call it
        if choice == "1":
            sign_or_verif = Prompt.ask("[bold blue]Would you like to sign or verify a message (s/v)").lower()

            if sign_or_verif == "s":
                message = Prompt.ask("[bold blue]Enter the message to sign: [/bold blue]")
                signature = ECSignature.sign_message(private_key, message)

                print(f"[bold yellow]Message:[/bold yellow] {message}")
                print(f"[bold yellow]Signature:[/bold yellow] {signature}")

                verify = Prompt.ask("[bold blue]Verify the signature?: [/bold blue]", choices=["y", "n"], default="y")
                if verify == "y":
                    is_valid = ECSignature.verify_signature(public_key, message, signature)
                    print("[bold green]Signature valid![/bold green]" if is_valid else "[bold red]Signature invalid.[/bold red]")

            elif sign_or_verif == "v":
                try:
                    verif_file = Prompt.ask("[bold blue]Input a filepath for the public key you want to check: [/bold blue]")
                    with open(verif_file, "rb") as f:
                        verif_key = serialization.load_pem_public_key(f.read(), backend=default_backend())
                except FileNotFoundError:
                    print("[bold red]Invalid key file. Please try again.[/bold red]")
                    break

                message = Prompt.ask("[bold blue]Enter the message to check: [/bold blue]")
                signature = Prompt.ask("[bold blue]Enter the signature attatched to the message: [/bold blue]")
                is_valid = ECSignature.verify_signature(verif_key, message, signature)
                print("[bold green]Signature valid![/bold green]" if is_valid else "[bold red]Signature invalid.[/bold red]")

            else:
                print("[bold red]Invalid choice. Please try again.[/bold red]")

        elif choice == "2":
            enc_or_dec = Prompt.ask("[bold blue]Do you want to encrypt or decrypt? (e/d): [/bold blue]").lower()

            if enc_or_dec == "e":
                message = Prompt.ask("[bold blue]Enter the message to encrypt: [/bold blue]")
                encrypted_message = ECHybridEncryption.encrypt_message(public_key, message, private_key)
                encrypted_message = str(encrypted_message)[2:-1]
                print(f"[bold yellow]Encrypted Message:[/bold yellow] {encrypted_message}")

            elif enc_or_dec == "d":
                encrypted_message = Prompt.ask("[bold blue]Enter the encrypted message to decrypt: [/bold blue]")
                if encrypted_message.startswith("b'") and encrypted_message.endswith("'"):
                    encrypted_message = encrypted_message[2:-1]
                decrypted_message = ECHybridEncryption.decrypt_message(private_key, encrypted_message, public_key)
                print(f"[bold green]Decrypted Message:[/bold green] {decrypted_message}")

            else:
                print("[bold red]Invalid choice. Please try again.[/bold red]")

        elif choice == "3":
            print("[bold green]Goodbye![/bold green]")
            break

        else:
            print("[bold red]Invalid choice. Please try again.[/bold red]")
    