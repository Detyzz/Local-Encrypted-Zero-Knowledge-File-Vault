#!/usr/bin/env python3
"""Local encrypted file vault using AES-256-GCM and PBKDF2-HMAC-SHA256."""

from __future__ import annotations

import argparse
import getpass
import os
import struct
import sys
import tempfile
from pathlib import Path

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC


MAGIC = b"ZKV1"
SALT_SIZE = 16
NONCE_SIZE = 12
TAG_SIZE = 16
KEY_SIZE = 32
DEFAULT_ITERATIONS = 600_000
DEFAULT_CHUNK_SIZE = 1024 * 1024
HEADER_FORMAT = ">4sI16s12s"
HEADER_SIZE = struct.calcsize(HEADER_FORMAT)


class VaultError(Exception):
    """Raised when a recoverable vault operation fails."""


def wipe_buffer(buffer: bytearray | memoryview | None) -> None:
    """Best-effort overwrite of mutable sensitive buffers."""
    if buffer is None:
        return
    for index in range(len(buffer)):
        buffer[index] = 0


def password_to_bytes(password: str) -> bytearray:
    encoded = bytearray(password.encode("utf-8"))
    return encoded


def prompt_password(confirm: bool = False) -> bytearray:
    password = getpass.getpass("Master password: ")
    if confirm:
        repeated = getpass.getpass("Confirm password: ")
        if password != repeated:
            raise VaultError("Passwords do not match.")
    if len(password) < 8:
        raise VaultError("Use a master password with at least 8 characters.")
    return password_to_bytes(password)


def derive_key(password: bytearray, salt: bytes, iterations: int) -> bytearray:
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=KEY_SIZE,
        salt=salt,
        iterations=iterations,
        backend=default_backend(),
    )
    return bytearray(kdf.derive(bytes(password)))


def require_readable_file(path: Path) -> None:
    if not path.exists():
        raise VaultError(f"Input file does not exist: {path}")
    if not path.is_file():
        raise VaultError(f"Input path is not a file: {path}")


def prepare_output(path: Path, force: bool) -> None:
    if path.exists() and not force:
        raise VaultError(f"Output file already exists: {path} (use --force to overwrite)")


def default_encrypt_output(input_path: Path) -> Path:
    return input_path.with_name(input_path.name + ".zvault")


def default_decrypt_output(input_path: Path) -> Path:
    if input_path.name.endswith(".zvault"):
        return input_path.with_name(input_path.name[:-7])
    return input_path.with_suffix(input_path.suffix + ".decrypted")


def encrypt_file(
    input_path: Path,
    output_path: Path,
    password: bytearray,
    iterations: int = DEFAULT_ITERATIONS,
    chunk_size: int = DEFAULT_CHUNK_SIZE,
    force: bool = False,
) -> None:
    require_readable_file(input_path)
    prepare_output(output_path, force)

    salt = os.urandom(SALT_SIZE)
    nonce = os.urandom(NONCE_SIZE)
    header = struct.pack(HEADER_FORMAT, MAGIC, iterations, salt, nonce)
    key = derive_key(password, salt, iterations)

    try:
        cipher = Cipher(algorithms.AES(bytes(key)), modes.GCM(nonce), backend=default_backend())
        encryptor = cipher.encryptor()
        encryptor.authenticate_additional_data(header)

        with input_path.open("rb") as source, output_path.open("wb") as target:
            target.write(header)
            while True:
                chunk = source.read(chunk_size)
                if not chunk:
                    break
                target.write(encryptor.update(chunk))
            encryptor.finalize()
            target.write(encryptor.tag)
    finally:
        wipe_buffer(key)


def decrypt_file(
    input_path: Path,
    output_path: Path,
    password: bytearray,
    chunk_size: int = DEFAULT_CHUNK_SIZE,
    force: bool = False,
) -> None:
    require_readable_file(input_path)
    prepare_output(output_path, force)

    file_size = input_path.stat().st_size
    if file_size < HEADER_SIZE + TAG_SIZE:
        raise VaultError("Encrypted file is too small or corrupted.")

    with input_path.open("rb") as source:
        header = source.read(HEADER_SIZE)
        try:
            magic, iterations, salt, nonce = struct.unpack(HEADER_FORMAT, header)
        except struct.error as exc:
            raise VaultError("Encrypted file header is invalid.") from exc

        if magic != MAGIC:
            raise VaultError("Unsupported file format or wrong vault file.")

        source.seek(file_size - TAG_SIZE)
        tag = source.read(TAG_SIZE)
        ciphertext_size = file_size - HEADER_SIZE - TAG_SIZE

        key = derive_key(password, salt, iterations)
        temp_path: Path | None = None

        try:
            cipher = Cipher(
                algorithms.AES(bytes(key)),
                modes.GCM(nonce, tag),
                backend=default_backend(),
            )
            decryptor = cipher.decryptor()
            decryptor.authenticate_additional_data(header)

            output_path.parent.mkdir(parents=True, exist_ok=True)
            with tempfile.NamedTemporaryFile(
                "wb",
                delete=False,
                dir=str(output_path.parent),
                prefix=f".{output_path.name}.",
                suffix=".tmp",
            ) as temp_file:
                temp_path = Path(temp_file.name)
                source.seek(HEADER_SIZE)
                remaining = ciphertext_size

                while remaining > 0:
                    chunk = source.read(min(chunk_size, remaining))
                    if not chunk:
                        raise VaultError("Encrypted file ended unexpectedly.")
                    remaining -= len(chunk)
                    temp_file.write(decryptor.update(chunk))

                decryptor.finalize()

            os.replace(temp_path, output_path)
            temp_path = None
        except InvalidTag as exc:
            raise VaultError("Decryption failed. The password is wrong or the file was modified.") from exc
        finally:
            wipe_buffer(key)
            if temp_path and temp_path.exists():
                temp_path.unlink(missing_ok=True)


def positive_int(value: str) -> int:
    parsed = int(value)
    if parsed <= 0:
        raise argparse.ArgumentTypeError("must be a positive integer")
    return parsed


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Encrypt and decrypt local files with AES-256-GCM.",
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    encrypt = subparsers.add_parser("encrypt", help="Encrypt a file")
    encrypt.add_argument("input", type=Path, help="File to encrypt")
    encrypt.add_argument("-o", "--output", type=Path, help="Encrypted output path")
    encrypt.add_argument("-f", "--force", action="store_true", help="Overwrite output file")
    encrypt.add_argument(
        "--iterations",
        type=positive_int,
        default=DEFAULT_ITERATIONS,
        help=f"PBKDF2 iterations (default: {DEFAULT_ITERATIONS})",
    )
    encrypt.add_argument(
        "--chunk-size",
        type=positive_int,
        default=DEFAULT_CHUNK_SIZE,
        help="Streaming chunk size in bytes",
    )

    decrypt = subparsers.add_parser("decrypt", help="Decrypt a .zvault file")
    decrypt.add_argument("input", type=Path, help="File to decrypt")
    decrypt.add_argument("-o", "--output", type=Path, help="Decrypted output path")
    decrypt.add_argument("-f", "--force", action="store_true", help="Overwrite output file")
    decrypt.add_argument(
        "--chunk-size",
        type=positive_int,
        default=DEFAULT_CHUNK_SIZE,
        help="Streaming chunk size in bytes",
    )

    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    try:
        if args.command == "encrypt":
            output = args.output or default_encrypt_output(args.input)
            password = prompt_password(confirm=True)
            try:
                encrypt_file(
                    args.input,
                    output,
                    password,
                    iterations=args.iterations,
                    chunk_size=args.chunk_size,
                    force=args.force,
                )
            finally:
                wipe_buffer(password)
            print(f"Encrypted: {output}")
            return 0

        if args.command == "decrypt":
            output = args.output or default_decrypt_output(args.input)
            password = prompt_password(confirm=False)
            try:
                decrypt_file(
                    args.input,
                    output,
                    password,
                    chunk_size=args.chunk_size,
                    force=args.force,
                )
            finally:
                wipe_buffer(password)
            print(f"Decrypted: {output}")
            return 0

        parser.error("Unknown command.")
        return 2
    except VaultError as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 1
    except KeyboardInterrupt:
        print("\nCancelled.", file=sys.stderr)
        return 130


if __name__ == "__main__":
    raise SystemExit(main())
