#!/usr/bin/env python3

import argparse
import base64
import hashlib
import math
import platform
import resource
import shutil
import statistics
import subprocess
import tempfile
import time
from dataclasses import dataclass
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
DEFAULT_BASE_KEY = (
    ROOT / "bad-public-keys/large-modulus-large-exponent/rsa_key.pem"
)
DEFAULT_OUTPUT = ROOT / "bad-secret-keys"
MESSAGE = b"kaboom"
RSA_ENCRYPTION_ALGORITHM = bytes.fromhex("300d06092a864886f70d0101010500")
SHA256_DIGEST_INFO = bytes.fromhex("3031300d060960864801650304020105000420")


@dataclass(frozen=True)
class Case:
    name: str
    power: int = 1
    large_e: bool = False
    dense_private_exponent: bool = False
    dense_crt_exponents: bool = False
    inconsistent_coefficient: bool = False
    openssl_verifies: bool = True


CASES = {
    case.name: case
    for case in (
        Case("large-modulus", power=2, openssl_verifies=False),
        Case("oversized-congruent-crt-exponents", dense_crt_exponents=True),
        Case("inconsistent-crt-coefficient", inconsistent_coefficient=True),
        Case("large-public-exponent", large_e=True, openssl_verifies=False),
        Case(
            "combined-worst-case",
            large_e=True,
            dense_private_exponent=True,
            dense_crt_exponents=True,
            inconsistent_coefficient=True,
            openssl_verifies=False,
        ),
    )
}


def read_tlv(data: bytes, offset: int = 0) -> tuple[int, bytes, int]:
    if offset + 2 > len(data):
        raise ValueError("truncated DER header")
    tag = data[offset]
    first_length = data[offset + 1]
    offset += 2
    if first_length < 0x80:
        length = first_length
    else:
        length_bytes = first_length & 0x7F
        if length_bytes == 0 or offset + length_bytes > len(data):
            raise ValueError("invalid DER length")
        length = int.from_bytes(data[offset : offset + length_bytes], "big")
        offset += length_bytes
    end = offset + length
    if end > len(data):
        raise ValueError("truncated DER value")
    return tag, data[offset:end], end


def children(data: bytes) -> list[tuple[int, bytes]]:
    values = []
    offset = 0
    while offset < len(data):
        tag, value, offset = read_tlv(data, offset)
        values.append((tag, value))
    return values


def der_length(length: int) -> bytes:
    if length < 0x80:
        return bytes([length])
    encoded = length.to_bytes((length.bit_length() + 7) // 8, "big")
    return bytes([0x80 | len(encoded)]) + encoded


def der_tlv(tag: int, value: bytes) -> bytes:
    return bytes([tag]) + der_length(len(value)) + value


def der_integer(value: int) -> bytes:
    if value < 0:
        raise ValueError("RSA fields must be nonnegative")
    encoded = value.to_bytes(max(1, (value.bit_length() + 7) // 8), "big")
    if encoded[0] & 0x80:
        encoded = bytes([0]) + encoded
    return der_tlv(0x02, encoded)


def der_sequence(*values: bytes) -> bytes:
    return der_tlv(0x30, b"".join(values))


def decode_pem(path: Path) -> bytes:
    lines = path.read_text().splitlines()
    payload = "".join(line for line in lines if not line.startswith("-----"))
    return base64.b64decode(payload, validate=True)


def encode_pem(label: str, der: bytes) -> str:
    payload = base64.b64encode(der).decode()
    lines = [f"-----BEGIN {label}-----"]
    lines.extend(payload[index : index + 64] for index in range(0, len(payload), 64))
    lines.append(f"-----END {label}-----")
    return "\n".join(lines) + "\n"


def parse_private_key(path: Path) -> list[int]:
    der = decode_pem(path)
    tag, pkcs8, end = read_tlv(der)
    if tag != 0x30 or end != len(der):
        raise ValueError("expected one PKCS#8 sequence")
    outer = children(pkcs8)
    if [item[0] for item in outer] != [0x02, 0x30, 0x04]:
        raise ValueError("unexpected PKCS#8 layout")
    tag, pkcs1, end = read_tlv(outer[2][1])
    if tag != 0x30 or end != len(outer[2][1]):
        raise ValueError("expected one RSAPrivateKey sequence")
    fields = children(pkcs1)
    if len(fields) != 9 or any(tag != 0x02 for tag, _ in fields):
        raise ValueError("expected the nine two-prime RSA fields")
    return [int.from_bytes(value, "big") for _, value in fields]


def write_private_key(path: Path, fields: list[int]) -> None:
    pkcs1 = der_sequence(*(der_integer(value) for value in fields))
    pkcs8 = der_sequence(
        der_integer(0),
        RSA_ENCRYPTION_ALGORITHM,
        der_tlv(0x04, pkcs1),
    )
    path.write_text(encode_pem("PRIVATE KEY", pkcs8))


def lcm(left: int, right: int) -> int:
    return left // math.gcd(left, right) * right


def dense_congruent(value: int, modulus: int, bits: int) -> int:
    if value.bit_length() >= bits:
        return value
    maximum = (1 << bits) - 1
    lifted = value + ((maximum - value) // modulus) * modulus
    if lifted.bit_length() != bits:
        raise ValueError(f"failed to construct a dense {bits}-bit value")
    return lifted


def validate_base(fields: list[int]) -> None:
    version, n, e, d, p, q, d_p, d_q, q_inv = fields
    lambda_n = lcm(p - 1, q - 1)
    checks = (
        version == 0,
        n == p * q,
        e * d % lambda_n == 1,
        d_p == d % (p - 1),
        d_q == d % (q - 1),
        q * q_inv % p == 1,
    )
    if not all(checks):
        raise ValueError("base key does not have consistent two-prime RSA parameters")


def powered_key(base: list[int], power: int) -> tuple[list[int], int, int, int]:
    _, _, e, _, base_p, base_q, _, _, _ = base
    p = pow(base_p, power)
    q = pow(base_q, power)
    n = p * q
    lambda_p = pow(base_p, power - 1) * (base_p - 1)
    lambda_q = pow(base_q, power - 1) * (base_q - 1)
    lambda_n = lcm(lambda_p, lambda_q)
    d = pow(e, -1, lambda_n)
    fields = [
        0,
        n,
        e,
        d,
        p,
        q,
        d % lambda_p,
        d % lambda_q,
        pow(q, -1, p),
    ]
    return fields, lambda_p, lambda_q, lambda_n


def build_case(base: list[int], case: Case, e_bits: int) -> list[int]:
    fields, lambda_p, lambda_q, lambda_n = powered_key(base, case.power)
    n_bits = fields[1].bit_length()
    if case.large_e:
        fields[2] = dense_congruent(fields[2], lambda_n, e_bits)
    if case.dense_private_exponent:
        fields[3] = dense_congruent(fields[3], lambda_n, n_bits)
    if case.dense_crt_exponents:
        fields[6] = dense_congruent(fields[6], lambda_p, n_bits)
        fields[7] = dense_congruent(fields[7], lambda_q, n_bits)
    if case.inconsistent_coefficient:
        fields[8] += 1
    return fields


def run(command: list[str], timeout: float) -> subprocess.CompletedProcess[bytes]:
    try:
        result = subprocess.run(
            command,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=timeout,
            check=False,
        )
    except subprocess.TimeoutExpired as error:
        raise RuntimeError(f"command timed out after {timeout:g}s: {' '.join(command)}") from error
    if result.returncode != 0:
        detail = result.stderr.decode(errors="replace").strip()
        raise RuntimeError(f"command failed: {' '.join(command)}\n{detail}")
    return result


def expected_encoded_message(message: bytes, modulus_bytes: int) -> bytes:
    digest_info = SHA256_DIGEST_INFO + hashlib.sha256(message).digest()
    padding_length = modulus_bytes - len(digest_info) - 3
    if padding_length < 8:
        raise ValueError("modulus is too short for PKCS#1 v1.5 SHA-256")
    return bytes([0, 1]) + bytes([0xFF]) * padding_length + bytes([0]) + digest_info


def verify_signature(fields: list[int], message: bytes, signature: bytes) -> None:
    _, n, e, _, p, q, _, _, _ = fields
    modulus_bytes = (n.bit_length() + 7) // 8
    if len(signature) != modulus_bytes:
        raise ValueError("signature length does not match the modulus")
    effective_e = e
    if e.bit_length() > n.bit_length() and p.bit_length() * 2 <= n.bit_length() + 1:
        effective_e %= lcm(p - 1, q - 1)
    recovered = pow(int.from_bytes(signature, "big"), effective_e, n)
    encoded = recovered.to_bytes(modulus_bytes, "big")
    if encoded != expected_encoded_message(message, modulus_bytes):
        raise ValueError("signature does not contain the expected SHA-256 digest")


def openssl_public_key(key: Path, output: Path, timeout: float) -> None:
    run(
        [
            "openssl",
            "pkey",
            "-provider",
            "default",
            "-in",
            str(key),
            "-pubout",
            "-out",
            str(output),
        ],
        timeout,
    )


def openssl_sign(key: Path, message: Path, output: Path, timeout: float) -> None:
    run(
        [
            "openssl",
            "dgst",
            "-provider",
            "default",
            "-sha256",
            "-sign",
            str(key),
            "-sigopt",
            "rsa_padding_mode:pkcs1",
            "-out",
            str(output),
            str(message),
        ],
        timeout,
    )


def openssl_verify(directory: Path, timeout: float) -> bool:
    result = subprocess.run(
        [
            "openssl",
            "dgst",
            "-provider",
            "default",
            "-sha256",
            "-verify",
            str(directory / "rsa_key.pub"),
            "-sigopt",
            "rsa_padding_mode:pkcs1",
            "-signature",
            str(directory / "signature.bin"),
            str(directory / "input.txt"),
        ],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        timeout=timeout,
        check=False,
    )
    return result.returncode == 0


def write_case(directory: Path, fields: list[int], timeout: float) -> None:
    directory.mkdir(parents=True)
    key = directory / "rsa_key.pem"
    message = directory / "input.txt"
    signature = directory / "signature.bin"
    write_private_key(key, fields)
    message.write_bytes(MESSAGE)
    openssl_public_key(key, directory / "rsa_key.pub", timeout)
    openssl_sign(key, message, signature, timeout)
    verify_signature(fields, MESSAGE, signature.read_bytes())
    encoded = base64.urlsafe_b64encode(signature.read_bytes()).rstrip(b"=")
    (directory / "signature.b64").write_bytes(encoded)


def selected_cases(names: list[str] | None) -> list[Case]:
    if not names:
        return list(CASES.values())
    return [CASES[name] for name in names]


def generate(args: argparse.Namespace) -> None:
    base = parse_private_key(args.base)
    validate_base(base)
    args.output.mkdir(parents=True, exist_ok=True)
    (ROOT / "tmp").mkdir(exist_ok=True)
    with tempfile.TemporaryDirectory(prefix="secret-key-generation-", dir=ROOT / "tmp") as tmp:
        temporary_root = Path(tmp)
        for case in selected_cases(args.case):
            destination = args.output / case.name
            if destination.exists() and not args.force:
                raise RuntimeError(f"{destination} exists; pass --force to replace it")
            fields = build_case(base, case, args.e_bits)
            temporary_case = temporary_root / case.name
            write_case(temporary_case, fields, args.timeout)
            if destination.exists():
                shutil.rmtree(destination)
            shutil.copytree(temporary_case, destination)
            print(f"generated {case.name}")


def check_case(
    base: list[int], case: Case, directory: Path, e_bits: int, timeout: float, quick: bool
) -> None:
    expected_fields = build_case(base, case, e_bits)
    actual_fields = parse_private_key(directory / "rsa_key.pem")
    if actual_fields != expected_fields:
        raise ValueError(f"{case.name}: private-key fields differ from the construction")
    if (directory / "input.txt").read_bytes() != MESSAGE:
        raise ValueError(f"{case.name}: input.txt differs from the corpus payload")
    signature = (directory / "signature.bin").read_bytes()
    encoded = base64.urlsafe_b64encode(signature).rstrip(b"=")
    if (directory / "signature.b64").read_bytes() != encoded:
        raise ValueError(f"{case.name}: signature.b64 does not match signature.bin")
    verify_signature(actual_fields, MESSAGE, signature)
    run(
        [
            "openssl",
            "pkey",
            "-provider",
            "default",
            "-in",
            str(directory / "rsa_key.pem"),
            "-noout",
        ],
        min(timeout, 5),
    )
    with tempfile.TemporaryDirectory(prefix=f"check-{case.name}-", dir=ROOT / "tmp") as tmp:
        temporary = Path(tmp)
        derived_public = temporary / "rsa_key.pub"
        openssl_public_key(directory / "rsa_key.pem", derived_public, min(timeout, 5))
        if derived_public.read_bytes() != (directory / "rsa_key.pub").read_bytes():
            raise ValueError(f"{case.name}: rsa_key.pub was not derived from rsa_key.pem")
        if not quick:
            regenerated_signature = temporary / "signature.bin"
            openssl_sign(
                directory / "rsa_key.pem",
                directory / "input.txt",
                regenerated_signature,
                timeout,
            )
            if regenerated_signature.read_bytes() != signature:
                raise ValueError(f"{case.name}: OpenSSL produced a different signature")
    verified = openssl_verify(directory, min(timeout, 10))
    if verified != case.openssl_verifies:
        raise ValueError(
            f"{case.name}: unexpected OpenSSL public verification result {verified}"
        )
    print(f"checked {case.name}")


def check(args: argparse.Namespace) -> None:
    base = parse_private_key(args.base)
    validate_base(base)
    (ROOT / "tmp").mkdir(exist_ok=True)
    for case in selected_cases(args.case):
        check_case(
            base,
            case,
            args.output / case.name,
            args.e_bits,
            args.timeout,
            args.quick,
        )


def profile_case(directory: Path, samples: int, timeout: float) -> None:
    timings = []
    user_cpu = []
    system_cpu = []
    (ROOT / "tmp").mkdir(exist_ok=True)
    with tempfile.TemporaryDirectory(prefix="profile-", dir=ROOT / "tmp") as tmp:
        for sample in range(samples):
            output = Path(tmp) / f"signature-{sample}.bin"
            before = resource.getrusage(resource.RUSAGE_CHILDREN)
            started = time.perf_counter()
            openssl_sign(
                directory / "rsa_key.pem",
                directory / "input.txt",
                output,
                timeout,
            )
            elapsed = time.perf_counter() - started
            after = resource.getrusage(resource.RUSAGE_CHILDREN)
            timings.append(elapsed)
            user_cpu.append(after.ru_utime - before.ru_utime)
            system_cpu.append(after.ru_stime - before.ru_stime)
            if output.read_bytes() != (directory / "signature.bin").read_bytes():
                raise ValueError(f"{directory.name}: profile signature differs")
            print(
                f"{directory.name} sample {sample + 1}: wall={elapsed:.3f}s "
                f"user={user_cpu[-1]:.3f}s sys={system_cpu[-1]:.3f}s"
            )
    print(
        f"{directory.name}: wall median={statistics.median(timings):.3f}s "
        f"range={min(timings):.3f}-{max(timings):.3f}s"
    )


def profile(args: argparse.Namespace) -> None:
    version = run(["openssl", "version"], 5).stdout.decode().strip()
    print(f"{version}; {platform.platform()}")
    for case in selected_cases(args.case):
        profile_case(args.output / case.name, args.samples, args.timeout)


def inspect(args: argparse.Namespace) -> None:
    names = ["version", "n", "e", "d", "p", "q", "dP", "dQ", "qInv"]
    for case in selected_cases(args.case):
        fields = parse_private_key(args.output / case.name / "rsa_key.pem")
        summary = ", ".join(
            f"{name}={value.bit_length()}" for name, value in zip(names, fields)
        )
        print(f"{case.name}: {summary}")


def add_common_options(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--base", type=Path, default=DEFAULT_BASE_KEY)
    parser.add_argument("--output", type=Path, default=DEFAULT_OUTPUT)
    parser.add_argument("--case", action="append", choices=CASES)
    parser.add_argument("--e-bits", type=int, default=1_048_576)


def main() -> None:
    parser = argparse.ArgumentParser()
    subparsers = parser.add_subparsers(dest="command", required=True)

    generate_parser = subparsers.add_parser("generate")
    add_common_options(generate_parser)
    generate_parser.add_argument("--timeout", type=float, default=90)
    generate_parser.add_argument("--force", action="store_true")
    generate_parser.set_defaults(function=generate)

    check_parser = subparsers.add_parser("check")
    add_common_options(check_parser)
    check_parser.add_argument("--timeout", type=float, default=90)
    check_parser.add_argument("--quick", action="store_true")
    check_parser.set_defaults(function=check)

    profile_parser = subparsers.add_parser("profile")
    add_common_options(profile_parser)
    profile_parser.add_argument("--timeout", type=float, default=90)
    profile_parser.add_argument("--samples", type=int, default=3)
    profile_parser.set_defaults(function=profile)

    inspect_parser = subparsers.add_parser("inspect")
    add_common_options(inspect_parser)
    inspect_parser.set_defaults(function=inspect)

    args = parser.parse_args()
    args.function(args)


if __name__ == "__main__":
    main()
