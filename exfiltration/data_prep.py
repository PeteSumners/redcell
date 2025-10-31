"""
Data Preparation Module

Prepare data for exfiltration with encryption, compression, and steganography.
"""

import os
import zipfile
import tarfile
import gzip
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from typing import Optional, List
import base64
import io


class DataPreparation:
    """
    Prepare data for exfiltration.

    Features:
    - AES-256-GCM encryption
    - Compression (zip, tar.gz, gzip)
    - Basic steganography
    - Chunking for large files
    """

    def __init__(self, encryption_key: bytes = None):
        """
        Initialize data preparation.

        Args:
            encryption_key: 32-byte encryption key (generated if not provided)
        """
        if encryption_key is None:
            self.encryption_key = AESGCM.generate_key(bit_length=256)
        else:
            self.encryption_key = encryption_key

        self.aesgcm = AESGCM(self.encryption_key)

    @staticmethod
    def derive_key_from_password(password: str, salt: bytes = None) -> tuple:
        """
        Derive encryption key from password.

        Args:
            password: Password string
            salt: Salt (generated if not provided)

        Returns:
            Tuple of (key, salt)
        """
        if salt is None:
            salt = os.urandom(16)

        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=100000,
        )

        key = kdf.derive(password.encode('utf-8'))

        return key, salt

    def encrypt_data(self, data: bytes) -> bytes:
        """
        Encrypt data with AES-256-GCM.

        Args:
            data: Data to encrypt

        Returns:
            Encrypted data (nonce + ciphertext + tag)
        """
        # Generate nonce
        nonce = os.urandom(12)

        # Encrypt
        ciphertext = self.aesgcm.encrypt(nonce, data, None)

        # Return nonce + ciphertext
        return nonce + ciphertext

    def decrypt_data(self, encrypted_data: bytes) -> bytes:
        """
        Decrypt AES-256-GCM encrypted data.

        Args:
            encrypted_data: Encrypted data (nonce + ciphertext + tag)

        Returns:
            Decrypted data
        """
        # Extract nonce
        nonce = encrypted_data[:12]
        ciphertext = encrypted_data[12:]

        # Decrypt
        plaintext = self.aesgcm.decrypt(nonce, ciphertext, None)

        return plaintext

    def encrypt_file(
        self,
        input_file: str,
        output_file: str = None
    ) -> str:
        """
        Encrypt a file.

        Args:
            input_file: Input file path
            output_file: Output file path (auto-generated if not provided)

        Returns:
            Output file path
        """
        if output_file is None:
            output_file = input_file + '.enc'

        print(f"[*] Encrypting: {input_file}")

        with open(input_file, 'rb') as f:
            plaintext = f.read()

        encrypted = self.encrypt_data(plaintext)

        with open(output_file, 'wb') as f:
            f.write(encrypted)

        print(f"[+] Encrypted file: {output_file}")
        return output_file

    def decrypt_file(
        self,
        input_file: str,
        output_file: str = None
    ) -> str:
        """
        Decrypt a file.

        Args:
            input_file: Encrypted file path
            output_file: Output file path

        Returns:
            Output file path
        """
        if output_file is None:
            if input_file.endswith('.enc'):
                output_file = input_file[:-4]
            else:
                output_file = input_file + '.dec'

        print(f"[*] Decrypting: {input_file}")

        with open(input_file, 'rb') as f:
            encrypted = f.read()

        plaintext = self.decrypt_data(encrypted)

        with open(output_file, 'wb') as f:
            f.write(plaintext)

        print(f"[+] Decrypted file: {output_file}")
        return output_file

    @staticmethod
    def compress_zip(
        files: List[str],
        output_file: str,
        compression_level: int = 9
    ) -> str:
        """
        Compress files to ZIP archive.

        Args:
            files: List of file paths
            output_file: Output ZIP file
            compression_level: Compression level (0-9)

        Returns:
            Output file path
        """
        print(f"[*] Creating ZIP archive: {output_file}")

        with zipfile.ZipFile(output_file, 'w', zipfile.ZIP_DEFLATED, compresslevel=compression_level) as zipf:
            for file_path in files:
                if os.path.isfile(file_path):
                    arcname = os.path.basename(file_path)
                    zipf.write(file_path, arcname=arcname)
                    print(f"[+] Added: {file_path}")

        size = os.path.getsize(output_file)
        print(f"[+] Archive created: {output_file} ({size / (1024*1024):.2f} MB)")

        return output_file

    @staticmethod
    def compress_targz(
        files: List[str],
        output_file: str
    ) -> str:
        """
        Compress files to tar.gz archive.

        Args:
            files: List of file paths
            output_file: Output tar.gz file

        Returns:
            Output file path
        """
        print(f"[*] Creating tar.gz archive: {output_file}")

        with tarfile.open(output_file, 'w:gz') as tar:
            for file_path in files:
                if os.path.isfile(file_path):
                    arcname = os.path.basename(file_path)
                    tar.add(file_path, arcname=arcname)
                    print(f"[+] Added: {file_path}")

        size = os.path.getsize(output_file)
        print(f"[+] Archive created: {output_file} ({size / (1024*1024):.2f} MB)")

        return output_file

    @staticmethod
    def compress_gzip(input_file: str, output_file: str = None) -> str:
        """
        Compress file with gzip.

        Args:
            input_file: Input file
            output_file: Output file (auto-generated if not provided)

        Returns:
            Output file path
        """
        if output_file is None:
            output_file = input_file + '.gz'

        print(f"[*] Compressing with gzip: {input_file}")

        with open(input_file, 'rb') as f_in:
            with gzip.open(output_file, 'wb', compresslevel=9) as f_out:
                f_out.writelines(f_in)

        original_size = os.path.getsize(input_file)
        compressed_size = os.path.getsize(output_file)
        ratio = (1 - compressed_size / original_size) * 100

        print(f"[+] Compressed: {output_file}")
        print(f"[+] Compression ratio: {ratio:.1f}%")

        return output_file

    def compress_and_encrypt_directory(
        self,
        directory: str,
        output_file: str,
        format: str = 'zip'
    ) -> str:
        """
        Compress and encrypt an entire directory.

        Args:
            directory: Directory to compress
            output_file: Output file path
            format: Compression format (zip or targz)

        Returns:
            Encrypted archive path
        """
        print(f"[*] Compressing and encrypting directory: {directory}")

        # Collect all files
        files = []
        for root, dirs, filenames in os.walk(directory):
            for filename in filenames:
                file_path = os.path.join(root, filename)
                files.append(file_path)

        print(f"[*] Found {len(files)} files")

        # Compress
        temp_archive = output_file + '.tmp'

        if format == 'zip':
            self.compress_zip(files, temp_archive)
        elif format == 'targz':
            self.compress_targz(files, temp_archive)
        else:
            raise ValueError(f"Unknown format: {format}")

        # Encrypt
        final_output = self.encrypt_file(temp_archive, output_file)

        # Remove temp file
        os.remove(temp_archive)

        print(f"[+] Final encrypted archive: {final_output}")
        return final_output

    @staticmethod
    def hide_in_image(data: bytes, image_path: str, output_path: str) -> str:
        """
        Hide data in image using LSB steganography (basic).

        Args:
            data: Data to hide
            image_path: Original image path
            output_path: Output image path

        Returns:
            Output image path

        Note: Requires PIL/Pillow
        """
        try:
            from PIL import Image
        except ImportError:
            print("[-] PIL/Pillow not installed. Install: pip install Pillow")
            return None

        print(f"[*] Hiding data in image: {image_path}")

        # Open image
        img = Image.open(image_path)
        pixels = img.load()

        # Convert data to binary
        data_len = len(data)
        binary_data = ''.join(format(byte, '08b') for byte in data)

        # Add length header (32 bits)
        header = format(data_len, '032b')
        binary_data = header + binary_data

        # Check if image has enough capacity
        max_capacity = img.size[0] * img.size[1] * 3  # RGB channels
        if len(binary_data) > max_capacity:
            print(f"[-] Image too small. Need {len(binary_data)} bits, have {max_capacity}")
            return None

        # Hide data in LSB
        data_index = 0
        for y in range(img.size[1]):
            for x in range(img.size[0]):
                if data_index >= len(binary_data):
                    break

                pixel = list(pixels[x, y])

                for i in range(3):  # RGB
                    if data_index < len(binary_data):
                        # Modify LSB
                        pixel[i] = pixel[i] & 0xFE | int(binary_data[data_index])
                        data_index += 1

                pixels[x, y] = tuple(pixel)

            if data_index >= len(binary_data):
                break

        # Save modified image
        img.save(output_path)

        print(f"[+] Data hidden in: {output_path}")
        print(f"[+] Hidden {data_len} bytes")

        return output_path

    @staticmethod
    def extract_from_image(image_path: str) -> bytes:
        """
        Extract data hidden in image.

        Args:
            image_path: Image path

        Returns:
            Extracted data

        Note: Requires PIL/Pillow
        """
        try:
            from PIL import Image
        except ImportError:
            print("[-] PIL/Pillow not installed")
            return None

        print(f"[*] Extracting data from image: {image_path}")

        # Open image
        img = Image.open(image_path)
        pixels = img.load()

        # Extract length header (32 bits)
        binary_data = ''
        for y in range(img.size[1]):
            for x in range(img.size[0]):
                pixel = pixels[x, y]

                for i in range(3):  # RGB
                    binary_data += str(pixel[i] & 1)

                    if len(binary_data) == 32:
                        # Parse length
                        data_len = int(binary_data, 2)

                        # Extract data
                        bits_needed = data_len * 8
                        binary_data = ''

                        # Continue extracting
                        for y2 in range(y, img.size[1]):
                            start_x = x + 1 if y2 == y else 0

                            for x2 in range(start_x, img.size[0]):
                                pixel2 = pixels[x2, y2]

                                for i2 in range(3):
                                    binary_data += str(pixel2[i2] & 1)

                                    if len(binary_data) >= bits_needed:
                                        # Convert to bytes
                                        data = bytearray()
                                        for b in range(0, len(binary_data), 8):
                                            byte = int(binary_data[b:b+8], 2)
                                            data.append(byte)

                                        print(f"[+] Extracted {len(data)} bytes")
                                        return bytes(data[:data_len])

        return None

    def get_key_base64(self) -> str:
        """
        Get encryption key as base64 string.

        Returns:
            Base64-encoded key
        """
        return base64.b64encode(self.encryption_key).decode('utf-8')


def main():
    """Main function for standalone usage."""
    import argparse

    parser = argparse.ArgumentParser(description='RedCell Data Preparation')

    subparsers = parser.add_subparsers(dest='mode', help='Mode')

    # Encrypt
    encrypt_parser = subparsers.add_parser('encrypt', help='Encrypt file')
    encrypt_parser.add_argument('--input', required=True, help='Input file')
    encrypt_parser.add_argument('--output', help='Output file')
    encrypt_parser.add_argument('--password', help='Password (instead of random key)')

    # Decrypt
    decrypt_parser = subparsers.add_parser('decrypt', help='Decrypt file')
    decrypt_parser.add_argument('--input', required=True, help='Encrypted file')
    decrypt_parser.add_argument('--output', help='Output file')
    decrypt_parser.add_argument('--key', required=True, help='Base64 encryption key')

    # Compress
    compress_parser = subparsers.add_parser('compress', help='Compress files')
    compress_parser.add_argument('--files', nargs='+', required=True, help='Files to compress')
    compress_parser.add_argument('--output', required=True, help='Output archive')
    compress_parser.add_argument('--format', choices=['zip', 'targz'], default='zip', help='Format')

    # Hide in image
    steg_parser = subparsers.add_parser('hide', help='Hide data in image')
    steg_parser.add_argument('--data', required=True, help='Data file to hide')
    steg_parser.add_argument('--image', required=True, help='Cover image')
    steg_parser.add_argument('--output', required=True, help='Output image')

    # Extract from image
    extract_parser = subparsers.add_parser('extract', help='Extract data from image')
    extract_parser.add_argument('--image', required=True, help='Stego image')
    extract_parser.add_argument('--output', required=True, help='Output file')

    args = parser.parse_args()

    if args.mode == 'encrypt':
        if args.password:
            key, salt = DataPreparation.derive_key_from_password(args.password)
            prep = DataPreparation(encryption_key=key)
            print(f"[*] Salt (save this): {base64.b64encode(salt).decode('utf-8')}")
        else:
            prep = DataPreparation()

        prep.encrypt_file(args.input, args.output)
        print(f"[*] Encryption key: {prep.get_key_base64()}")

    elif args.mode == 'decrypt':
        key = base64.b64decode(args.key)
        prep = DataPreparation(encryption_key=key)
        prep.decrypt_file(args.input, args.output)

    elif args.mode == 'compress':
        if args.format == 'zip':
            DataPreparation.compress_zip(args.files, args.output)
        elif args.format == 'targz':
            DataPreparation.compress_targz(args.files, args.output)

    elif args.mode == 'hide':
        with open(args.data, 'rb') as f:
            data = f.read()

        DataPreparation.hide_in_image(data, args.image, args.output)

    elif args.mode == 'extract':
        data = DataPreparation.extract_from_image(args.image)

        if data:
            with open(args.output, 'wb') as f:
                f.write(data)
            print(f"[+] Saved to: {args.output}")

    else:
        parser.print_help()


if __name__ == '__main__':
    main()
