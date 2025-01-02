from eccx import ECKeyManager, ECSignature, ECHybridEncryption
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from rich.prompt import Prompt
import os

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
    