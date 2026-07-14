#!/usr/bin/env python3

import argparse
import base64
import gzip
import hashlib
import io
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

from rsa_secret_key_fixtures import (
    MESSAGE,
    RSA_ENCRYPTION_ALGORITHM,
    children,
    decode_pem,
    der_integer,
    der_sequence,
    der_tlv,
    encode_pem,
    expected_encoded_message,
    lcm,
    openssl_public_key,
    openssl_sign,
    parse_private_key,
    read_tlv,
    run,
    validate_base,
    write_private_key,
)


ROOT = Path(__file__).resolve().parents[1]
DEFAULT_OUTPUT = ROOT / "bad-public-keys"
DEFAULT_BASE_KEY = (
    DEFAULT_OUTPUT / "large-modulus-large-exponent" / "rsa_key.pem"
)
DEFAULT_PARSER_BITS = 268_435_456


@dataclass(frozen=True)
class SignableCase:
    name: str
    generated: bool


@dataclass(frozen=True)
class ParserCase:
    name: str
    generated: bool
    compressed: bool
    n_bits: int
    e_bits: int
    n_kind: str
    e_kind: str
    expanded_limit: int


SIGNABLE_CASES = {
    case.name: case
    for case in (
        SignableCase("large-modulus-large-exponent", False),
        SignableCase("large-modulus-large-exponent2", False),
        SignableCase("large-modulus", True),
        SignableCase("maximum-modulus-and-exponent", True),
        SignableCase("maximum-unrestricted-exponent", True),
    )
}
PARSER_CASES = {
    case.name: case
    for case in (
        ParserCase("all-zeros", False, False, 0, 0, "zero", "zero", 4096),
        ParserCase(
            "huge-modulus-and-exponent",
            False,
            True,
            80_000_000,
            8_000,
            "ones",
            "ones",
            16 * 1024 * 1024,
        ),
        ParserCase(
            "huge-modulus",
            True,
            True,
            DEFAULT_PARSER_BITS,
            17,
            "ones",
            "65537",
            48 * 1024 * 1024,
        ),
        ParserCase(
            "huge-public-exponent",
            True,
            True,
            16_384,
            DEFAULT_PARSER_BITS,
            "base",
            "ones",
            48 * 1024 * 1024,
        ),
    )
}
ALL_CASES = SIGNABLE_CASES | PARSER_CASES


@dataclass(frozen=True)
class PublicFields:
    n: int
    e: int
    n_raw: bytes
    e_raw: bytes


def public_der(n: int, e: int) -> bytes:
    key = der_sequence(der_integer(n), der_integer(e))
    return der_sequence(
        RSA_ENCRYPTION_ALGORITHM,
        der_tlv(0x03, bytes([0]) + key),
    )


def parse_public_der(der: bytes) -> PublicFields:
    tag, spki, end = read_tlv(der)
    if tag != 0x30 or end != len(der):
        raise ValueError("expected one SubjectPublicKeyInfo sequence")
    outer = children(spki)
    if [item[0] for item in outer] != [0x30, 0x03]:
        raise ValueError("unexpected SubjectPublicKeyInfo layout")
    if der_tlv(0x30, outer[0][1]) != RSA_ENCRYPTION_ALGORITHM:
        raise ValueError("expected the rsaEncryption algorithm identifier")
    if not outer[1][1] or outer[1][1][0] != 0:
        raise ValueError("unsupported BIT STRING padding")
    key_der = outer[1][1][1:]
    tag, key, end = read_tlv(key_der)
    if tag != 0x30 or end != len(key_der):
        raise ValueError("expected one RSAPublicKey sequence")
    values = children(key)
    if len(values) != 2 or any(tag != 0x02 for tag, _ in values):
        raise ValueError("expected modulus and public exponent INTEGERs")
    n_raw, e_raw = values[0][1], values[1][1]
    return PublicFields(
        int.from_bytes(n_raw, "big"),
        int.from_bytes(e_raw, "big"),
        n_raw,
        e_raw,
    )


def read_gzip(path: Path, expanded_limit: int) -> bytes:
    output = bytearray()
    with gzip.open(path, "rb") as source:
        while chunk := source.read(1024 * 1024):
            output.extend(chunk)
            if len(output) > expanded_limit:
                raise ValueError(f"{path} exceeds its expanded-size limit")
    return bytes(output)


def decode_pem_bytes(pem: bytes) -> bytes:
    payload = b"".join(
        line for line in pem.splitlines() if not line.startswith(b"-----")
    )
    return base64.b64decode(payload, validate=True)


def read_public(path: Path, expanded_limit: int = 1024 * 1024) -> PublicFields:
    if path.suffix == ".gz":
        pem = read_gzip(path, expanded_limit)
        return parse_public_der(decode_pem_bytes(pem))
    return parse_public_der(decode_pem(path))


def deterministic_gzip(data: bytes) -> bytes:
    output = io.BytesIO()
    with gzip.GzipFile(
        filename="", fileobj=output, mode="wb", compresslevel=9, mtime=0
    ) as destination:
        destination.write(data)
    return output.getvalue()


def probable_prime(value: int) -> bool:
    small_primes = (2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37, 41, 43, 47)
    for prime in small_primes:
        if value % prime == 0:
            return value == prime
    odd = value - 1
    exponent = 0
    while odd % 2 == 0:
        odd //= 2
        exponent += 1
    bases = small_primes + tuple(
        int.from_bytes(hashlib.sha256(f"badrsa-{index}".encode()).digest(), "big")
        for index in range(32)
    )
    for base in bases:
        base = 2 + base % (value - 3)
        witness = pow(base, odd, value)
        if witness in (1, value - 1):
            continue
        for _ in range(exponent - 1):
            witness = pow(witness, 2, value)
            if witness == value - 1:
                break
        else:
            return False
    return True


def near_maximum_prime(bits: int, offset: int) -> int:
    candidate = ((1 << bits) - 1 - offset) | 1
    for _ in range(1_000_000):
        if probable_prime(candidate):
            return candidate
        candidate -= 2
    raise RuntimeError("prime search exhausted")


def fields_from_factors(p: int, q: int, e: int) -> list[int]:
    n = p * q
    lambda_n = lcm(p - 1, q - 1)
    d = pow(e, -1, lambda_n)
    return [
        0,
        n,
        e,
        d,
        p,
        q,
        d % (p - 1),
        d % (q - 1),
        pow(q, -1, p),
    ]


def build_signable_case(
    name: str, base: list[int]
) -> list[int]:
    _, _, _, _, p, q, _, _, _ = base
    if name == "large-modulus":
        return fields_from_factors(p, q, 65537)
    if name == "maximum-modulus-and-exponent":
        return fields_from_factors(p, q, (1 << 64) - 1)
    if name == "maximum-unrestricted-exponent":
        p = near_maximum_prime(1536, 0)
        q = near_maximum_prime(1536, 1_000_000)
        n = p * q
        e = ((n >> 1536) << 1536) - 1
        lambda_n = lcm(p - 1, q - 1)
        while math.gcd(e, lambda_n) != 1:
            e -= 2
        return fields_from_factors(p, q, e)
    raise ValueError(f"{name} is not a generated signable case")


def parser_values(name: str, parser_bits: int, base_n: int) -> tuple[int, int]:
    if name == "huge-modulus":
        return (1 << parser_bits) - 1, 65537
    if name == "huge-public-exponent":
        return base_n, (1 << parser_bits) - 1
    raise ValueError(f"{name} is not a generated parser case")


def verify_signature(fields: PublicFields, message: bytes, signature: bytes) -> None:
    modulus_bytes = (fields.n.bit_length() + 7) // 8
    if len(signature) != modulus_bytes:
        raise ValueError("signature length does not match the modulus")
    recovered = pow(int.from_bytes(signature, "big"), fields.e, fields.n)
    encoded = recovered.to_bytes(modulus_bytes, "big")
    if encoded != expected_encoded_message(message, modulus_bytes):
        raise ValueError("signature does not contain the expected SHA-256 digest")


def write_signable_case(directory: Path, fields: list[int], timeout: float) -> None:
    directory.mkdir(parents=True)
    key = directory / "rsa_key.pem"
    message = directory / "input.txt"
    signature = directory / "signature.bin"
    write_private_key(key, fields)
    message.write_bytes(MESSAGE)
    openssl_public_key(key, directory / "rsa_key.pub", timeout)
    openssl_sign(key, message, signature, timeout)
    public = read_public(directory / "rsa_key.pub")
    verify_signature(public, MESSAGE, signature.read_bytes())
    encoded = base64.urlsafe_b64encode(signature.read_bytes()).rstrip(b"=")
    (directory / "signature.b64").write_bytes(encoded)


def write_parser_case(
    directory: Path, name: str, parser_bits: int, base_n: int
) -> None:
    directory.mkdir(parents=True)
    n, e = parser_values(name, parser_bits, base_n)
    pem = encode_pem("PUBLIC KEY", public_der(n, e)).encode()
    (directory / "rsa_key.pub.gz").write_bytes(deterministic_gzip(pem))


def selected_cases(names: list[str] | None) -> list[str]:
    if not names:
        return list(ALL_CASES)
    return names


def generate(args: argparse.Namespace) -> None:
    base = parse_private_key(args.base)
    validate_base(base)
    generated_names = args.case or [
        name for name, case in SIGNABLE_CASES.items() if case.generated
    ]
    for name in generated_names:
        case = ALL_CASES[name]
        if not case.generated:
            raise ValueError(f"{name} is an existing fixture, not a generated case")
        if isinstance(case, ParserCase) and not args.allow_parser_stress:
            raise ValueError("parser cases require --allow-parser-stress")
    args.output.mkdir(parents=True, exist_ok=True)
    (ROOT / "tmp").mkdir(exist_ok=True)
    with tempfile.TemporaryDirectory(prefix="public-key-generation-", dir=ROOT / "tmp") as tmp:
        temporary_root = Path(tmp)
        for name in generated_names:
            destination = args.output / name
            if destination.exists() and not args.force:
                raise RuntimeError(f"{destination} exists; pass --force to replace it")
            case = ALL_CASES[name]
            temporary_case = temporary_root / name
            if isinstance(case, SignableCase):
                fields = build_signable_case(name, base)
                write_signable_case(temporary_case, fields, args.timeout)
            else:
                write_parser_case(temporary_case, name, args.parser_bits, base[1])
            if destination.exists():
                shutil.rmtree(destination)
            shutil.copytree(temporary_case, destination)
            print(f"generated {name}")


def openssl_load(key: Path, timeout: float) -> None:
    run(
        [
            "openssl",
            "pkey",
            "-provider",
            "default",
            "-pubin",
            "-in",
            str(key),
            "-noout",
        ],
        timeout,
    )


def openssl_pubcheck(key: Path, timeout: float) -> subprocess.CompletedProcess[bytes]:
    return subprocess.run(
        [
            "openssl",
            "pkey",
            "-provider",
            "default",
            "-pubin",
            "-in",
            str(key),
            "-pubcheck",
            "-noout",
        ],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        timeout=timeout,
        check=False,
    )


def openssl_verify(directory: Path, timeout: float) -> None:
    run(
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
        timeout,
    )


def openssl_encrypt(
    directory: Path, output: Path, timeout: float
) -> None:
    run(
        [
            "openssl",
            "pkeyutl",
            "-provider",
            "default",
            "-encrypt",
            "-pubin",
            "-inkey",
            str(directory / "rsa_key.pub"),
            "-in",
            str(directory / "input.txt"),
            "-out",
            str(output),
            "-pkeyopt",
            "rsa_padding_mode:oaep",
        ],
        timeout,
    )


def check_signable(
    name: str,
    case: SignableCase,
    base: list[int],
    output: Path,
    timeout: float,
    quick: bool,
) -> None:
    directory = output / name
    expected_files = {
        "input.txt",
        "rsa_key.pem",
        "rsa_key.pub",
        "signature.b64",
        "signature.bin",
    }
    actual_files = {path.name for path in directory.iterdir() if path.is_file()}
    if actual_files != expected_files:
        raise ValueError(f"{name}: unexpected artifact set {sorted(actual_files)}")
    private = parse_private_key(directory / "rsa_key.pem")
    if case.generated and private != build_signable_case(name, base):
        raise ValueError(f"{name}: private-key fields differ from the construction")
    public = read_public(directory / "rsa_key.pub")
    if (public.n, public.e) != (private[1], private[2]):
        raise ValueError(f"{name}: public and private fields differ")
    if (directory / "input.txt").read_bytes() != MESSAGE:
        raise ValueError(f"{name}: input.txt differs from the corpus payload")
    signature = (directory / "signature.bin").read_bytes()
    expected_base64 = base64.urlsafe_b64encode(signature).rstrip(b"=")
    if (directory / "signature.b64").read_bytes().strip() != expected_base64:
        raise ValueError(f"{name}: signature.b64 does not match signature.bin")
    verify_signature(public, MESSAGE, signature)
    openssl_load(directory / "rsa_key.pub", min(timeout, 5))
    (ROOT / "tmp").mkdir(exist_ok=True)
    with tempfile.TemporaryDirectory(prefix=f"check-{name}-", dir=ROOT / "tmp") as tmp:
        temporary = Path(tmp)
        derived_public = temporary / "rsa_key.pub"
        openssl_public_key(directory / "rsa_key.pem", derived_public, min(timeout, 5))
        if derived_public.read_bytes() != (directory / "rsa_key.pub").read_bytes():
            raise ValueError(f"{name}: rsa_key.pub was not derived from rsa_key.pem")
        if not quick:
            result = openssl_pubcheck(directory / "rsa_key.pub", timeout)
            if result.returncode != 0:
                raise ValueError(f"{name}: OpenSSL public check failed")
            openssl_verify(directory, timeout)
            openssl_encrypt(directory, temporary / "ciphertext.bin", timeout)
            regenerated = temporary / "signature.bin"
            openssl_sign(
                directory / "rsa_key.pem",
                directory / "input.txt",
                regenerated,
                timeout,
            )
            if regenerated.read_bytes() != signature:
                raise ValueError(f"{name}: OpenSSL produced a different signature")
    print(f"checked {name}")


def check_ones(raw: bytes, bits: int, label: str) -> None:
    expected_bytes = (bits + 7) // 8
    if len(raw) != expected_bytes + 1 or raw[0] != 0:
        raise ValueError(f"{label}: unexpected positive INTEGER width")
    if raw.count(0xFF, 1) != expected_bytes:
        raise ValueError(f"{label}: INTEGER is not all ones")


def check_parser(
    name: str,
    case: ParserCase,
    output: Path,
    parser_bits: int,
    base_n: int,
    timeout: float,
    quick: bool,
    allow_parser_stress: bool,
) -> None:
    directory = output / name
    filename = "rsa_key.pub.gz" if case.compressed else "rsa_key.pub"
    key = directory / filename
    if {path.name for path in directory.iterdir() if path.is_file()} != {filename}:
        raise ValueError(f"{name}: unexpected parser-case artifacts")
    if case.compressed and not allow_parser_stress:
        print(f"skipped {name}; pass --allow-parser-stress")
        return
    expanded_limit = case.expanded_limit
    if case.generated:
        expanded_limit = 64 * 1024 * 1024
    fields = read_public(key, expanded_limit)
    if name == "all-zeros":
        if fields.n != 0 or fields.e != 0:
            raise ValueError("all-zeros: RSA values are not zero")
        if len(fields.n_raw) != 1001 or len(fields.e_raw) != 101:
            raise ValueError("all-zeros: encoded INTEGER widths changed")
        if any(fields.n_raw) or any(fields.e_raw):
            raise ValueError("all-zeros: encoded INTEGERs are not zero-filled")
    if case.n_kind == "base" and fields.n != base_n:
        raise ValueError(f"{name}: modulus differs from the base key")
    if case.n_kind == "ones":
        check_ones(fields.n_raw, case.n_bits if not case.generated else parser_bits, name)
    if case.e_kind == "65537" and fields.e != 65537:
        raise ValueError(f"{name}: public exponent is not 65537")
    if case.e_kind == "ones":
        check_ones(fields.e_raw, case.e_bits if not case.generated else parser_bits, name)
    (ROOT / "tmp").mkdir(exist_ok=True)
    with tempfile.TemporaryDirectory(prefix=f"check-{name}-", dir=ROOT / "tmp") as tmp:
        temporary_key = Path(tmp) / "rsa_key.pub"
        if case.compressed:
            temporary_key.write_bytes(read_gzip(key, expanded_limit))
        else:
            temporary_key.write_bytes(key.read_bytes())
        openssl_load(temporary_key, timeout)
        if not quick:
            result = openssl_pubcheck(temporary_key, timeout)
            expected_success = name == "huge-public-exponent"
            if (result.returncode == 0) != expected_success:
                expectation = "succeed" if expected_success else "fail"
                raise ValueError(f"{name}: OpenSSL pubcheck did not {expectation}")
    print(f"checked {name}")


def check(args: argparse.Namespace) -> None:
    base = parse_private_key(args.base)
    validate_base(base)
    for name in selected_cases(args.case):
        case = ALL_CASES[name]
        if isinstance(case, SignableCase):
            check_signable(
                name, case, base, args.output, args.timeout, args.quick
            )
        else:
            check_parser(
                name,
                case,
                args.output,
                args.parser_bits,
                base[1],
                args.timeout,
                args.quick,
                args.allow_parser_stress,
            )


def inspect(args: argparse.Namespace) -> None:
    for name in selected_cases(args.case):
        case = ALL_CASES[name]
        if isinstance(case, ParserCase) and case.compressed:
            if not args.allow_parser_stress:
                print(f"skipped {name}; pass --allow-parser-stress")
                continue
            path = args.output / name / "rsa_key.pub.gz"
            limit = 64 * 1024 * 1024 if case.generated else case.expanded_limit
        else:
            path = args.output / name / "rsa_key.pub"
            limit = case.expanded_limit if isinstance(case, ParserCase) else 1024 * 1024
        fields = read_public(path, limit)
        print(
            f"{name}: n={fields.n.bit_length()} e={fields.e.bit_length()} "
            f"e_weight={fields.e.bit_count()} n_bytes={len(fields.n_raw)} "
            f"e_bytes={len(fields.e_raw)}"
        )


def command_for_operation(
    operation: str, directory: Path, key: Path, temporary: Path
) -> list[str]:
    if operation == "load":
        return [
            "openssl",
            "pkey",
            "-provider",
            "default",
            "-pubin",
            "-in",
            str(key),
            "-noout",
        ]
    if operation == "pubcheck":
        return [
            "openssl",
            "pkey",
            "-provider",
            "default",
            "-pubin",
            "-in",
            str(key),
            "-pubcheck",
            "-noout",
        ]
    if operation == "verify":
        return [
            "openssl",
            "dgst",
            "-provider",
            "default",
            "-sha256",
            "-verify",
            str(key),
            "-sigopt",
            "rsa_padding_mode:pkcs1",
            "-signature",
            str(directory / "signature.bin"),
            str(directory / "input.txt"),
        ]
    if operation == "encrypt":
        return [
            "openssl",
            "pkeyutl",
            "-provider",
            "default",
            "-encrypt",
            "-pubin",
            "-inkey",
            str(key),
            "-in",
            str(directory / "input.txt"),
            "-out",
            str(temporary / "ciphertext.bin"),
            "-pkeyopt",
            "rsa_padding_mode:oaep",
        ]
    raise ValueError(f"unknown operation {operation}")


def max_rss_mebibytes(usage: resource.struct_rusage) -> float:
    scale = 1024 * 1024 if platform.system() == "Darwin" else 1024
    return usage.ru_maxrss / scale


def profile(args: argparse.Namespace) -> None:
    if not args.case:
        raise ValueError("profile requires at least one --case")
    version = run(["openssl", "version"], 5).stdout.decode().strip()
    print(f"{version}; {platform.platform()}")
    (ROOT / "tmp").mkdir(exist_ok=True)
    for name in args.case:
        case = ALL_CASES[name]
        if isinstance(case, ParserCase) and args.operation != "load":
            if name != "huge-public-exponent" or args.operation != "pubcheck":
                raise ValueError(
                    "parser cases support only load, except pubcheck for "
                    "huge-public-exponent"
                )
        if isinstance(case, ParserCase) and case.compressed:
            if not args.allow_parser_stress:
                raise ValueError("compressed parser cases require --allow-parser-stress")
        directory = args.output / name
        with tempfile.TemporaryDirectory(prefix=f"profile-{name}-", dir=ROOT / "tmp") as tmp:
            temporary = Path(tmp)
            if isinstance(case, ParserCase) and case.compressed:
                limit = 64 * 1024 * 1024 if case.generated else case.expanded_limit
                key = temporary / "rsa_key.pub"
                key.write_bytes(read_gzip(directory / "rsa_key.pub.gz", limit))
            else:
                key = directory / "rsa_key.pub"
            command = command_for_operation(args.operation, directory, key, temporary)
            timings = []
            for sample in range(args.samples):
                before = resource.getrusage(resource.RUSAGE_CHILDREN)
                started = time.perf_counter()
                result = subprocess.run(
                    command,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    timeout=args.timeout,
                    check=False,
                )
                elapsed = time.perf_counter() - started
                after = resource.getrusage(resource.RUSAGE_CHILDREN)
                if result.returncode != 0:
                    detail = result.stderr.decode(errors="replace").strip()
                    raise RuntimeError(f"{name}: {args.operation} failed\n{detail}")
                timings.append(elapsed)
                user = after.ru_utime - before.ru_utime
                system = after.ru_stime - before.ru_stime
                print(
                    f"{name} {args.operation} sample {sample + 1}: "
                    f"wall={elapsed:.6f}s user={user:.6f}s sys={system:.6f}s "
                    f"maxrss={max_rss_mebibytes(after):.1f}MiB"
                )
            print(
                f"{name} {args.operation}: median={statistics.median(timings):.6f}s "
                f"range={min(timings):.6f}-{max(timings):.6f}s"
            )


def add_common_options(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--base", type=Path, default=DEFAULT_BASE_KEY)
    parser.add_argument("--output", type=Path, default=DEFAULT_OUTPUT)
    parser.add_argument("--case", action="append", choices=ALL_CASES)
    parser.add_argument("--parser-bits", type=int, default=DEFAULT_PARSER_BITS)
    parser.add_argument("--allow-parser-stress", action="store_true")


def main() -> None:
    parser = argparse.ArgumentParser()
    subparsers = parser.add_subparsers(dest="command", required=True)

    generate_parser = subparsers.add_parser("generate")
    add_common_options(generate_parser)
    generate_parser.add_argument("--timeout", type=float, default=20)
    generate_parser.add_argument("--force", action="store_true")
    generate_parser.set_defaults(function=generate)

    check_parser = subparsers.add_parser("check")
    add_common_options(check_parser)
    check_parser.add_argument("--timeout", type=float, default=20)
    check_parser.add_argument("--quick", action="store_true")
    check_parser.set_defaults(function=check)

    inspect_parser = subparsers.add_parser("inspect")
    add_common_options(inspect_parser)
    inspect_parser.set_defaults(function=inspect)

    profile_parser = subparsers.add_parser("profile")
    add_common_options(profile_parser)
    profile_parser.add_argument(
        "--operation", choices=("load", "pubcheck", "verify", "encrypt"), required=True
    )
    profile_parser.add_argument("--samples", type=int, default=3)
    profile_parser.add_argument("--timeout", type=float, default=20)
    profile_parser.set_defaults(function=profile)

    args = parser.parse_args()
    args.function(args)


if __name__ == "__main__":
    main()
