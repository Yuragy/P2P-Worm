import struct
import sys
import os
import hashlib
import argparse
from pathlib import Path
from typing import Tuple, Optional
import logging
MAGIC_SCOD = 0x444F4353 
MAX_SHELLCODE_SIZE = 10 * 1024 * 1024  
MIN_SHELLCODE_SIZE = 16  
SUPPORTED_ARCHS = {
    'x86': 1,
    'x64': 2,
    '32': 1,
    '64': 2,
    '1': 1,
    '2': 2
}

logging.basicConfig(
    level=logging.INFO,
    format='[%(levelname)s] %(message)s'
)
logger = logging.getLogger(__name__)


class SCODHeaderError(Exception):
    """Base exception for SCOD header errors"""
    pass


class ShellcodeValidator:
    """Shellcode validator"""
    
    @staticmethod
    def validate_size(data: bytes) -> None:
        """Validates shellcode size"""
        size = len(data)
        if size < MIN_SHELLCODE_SIZE:
            raise SCODHeaderError(
                f"Shellcode too small: {size} bytes. "
                f"Minimum: {MIN_SHELLCODE_SIZE} bytes"
            )
        if size > MAX_SHELLCODE_SIZE:
            raise SCODHeaderError(
                f"Shellcode too large: {size} bytes. "
                f"Maximum: {MAX_SHELLCODE_SIZE} bytes"
            )
    
    @staticmethod
    def detect_existing_header(data: bytes) -> bool:
        """Checks for existing SCOD header"""
        if len(data) >= 4:
            magic = struct.unpack('<I', data[:4])[0]
            return magic == MAGIC_SCOD
        return False
    
    @staticmethod
    def validate_shellcode_patterns(data: bytes, arch: int) -> Tuple[bool, Optional[str]]:
        """
        Basic shellcode pattern validation
        Returns (is_valid, warning_message)
        """
        if data[:100].count(b'\x00') > 50:
            return True, "Many null bytes detected at the beginning of shellcode"
        
        donut_signatures = [
            b'\x55\x89\xe5',  # push ebp; mov ebp, esp (x86)
            b'\x48\x89\x5c\x24',  # mov [rsp+X], rbx (x64)
            b'\xe8\x00\x00\x00\x00',  # call $+5 (delta)
        ]
        
        for sig in donut_signatures:
            if sig in data[:1000]:
                logger.debug(f"Donut signature detected: {sig.hex()}")
                break
        
        return True, None


class SCODHeader:
    """Class for working with SCOD header"""
    
    HEADER_SIZE = 12  # 4 (magic) + 1 (arch) + 4 (length) + 3 (reserved)
    
    def __init__(self, arch: int, shellcode_length: int):
        """
        Initialize header
        
        Args:
            arch: Architecture (1=x86, 2=x64)
            shellcode_length: Shellcode length in bytes
        """
        if arch not in [1, 2]:
            raise SCODHeaderError(f"Invalid architecture: {arch}. Must be 1 (x86) or 2 (x64)")
        
        self.magic = MAGIC_SCOD
        self.arch = arch
        self.length = shellcode_length
        self.reserved = b'\x00' * 3
    
    def to_bytes(self) -> bytes:
        """Serializes header to bytes"""
        header = struct.pack('<I', self.magic)  # magic (4 bytes, little-endian)
        header += struct.pack('<B', self.arch)   # arch (1 byte)
        header += struct.pack('<I', self.length) # length (4 bytes, little-endian)
        header += self.reserved                  # reserved (3 bytes)
        
        assert len(header) == self.HEADER_SIZE, f"Invalid header size: {len(header)}"
        return header
    
    @classmethod
    def from_bytes(cls, data: bytes) -> 'SCODHeader':
        """Deserializes header from bytes"""
        if len(data) < cls.HEADER_SIZE:
            raise SCODHeaderError(f"Insufficient data for header: {len(data)} < {cls.HEADER_SIZE}")
        
        magic = struct.unpack('<I', data[0:4])[0]
        if magic != MAGIC_SCOD:
            raise SCODHeaderError(f"Invalid magic: 0x{magic:08X} != 0x{MAGIC_SCOD:08X}")
        
        arch = struct.unpack('<B', data[4:5])[0]
        length = struct.unpack('<I', data[5:9])[0]
        
        return cls(arch, length)
    
    def __str__(self) -> str:
        """String representation of header"""
        return (
            f"SCOD Header:\n"
            f"  Magic: 0x{self.magic:08X} ('SCOD')\n"
            f"  Arch: {self.arch} ({'x64' if self.arch == 2 else 'x86'})\n"
            f"  Length: {self.length} bytes ({self.length / 1024:.2f} KB)\n"
        )


def parse_architecture(arch_str: str) -> int:
    """
    Parses architecture string to number
    
    Args:
        arch_str: Architecture string (x86, x64, 32, 64, 1, 2)
    
    Returns:
        int: 1 for x86, 2 for x64
    """
    arch_str = arch_str.lower().strip()
    if arch_str in SUPPORTED_ARCHS:
        return SUPPORTED_ARCHS[arch_str]
    else:
        raise SCODHeaderError(
            f"Unknown architecture: '{arch_str}'. "
            f"Supported: {', '.join(SUPPORTED_ARCHS.keys())}"
        )


def calculate_checksums(data: bytes) -> dict:
    """Calculates checksums for data"""
    return {
        'md5': hashlib.md5(data).hexdigest(),
        'sha1': hashlib.sha1(data).hexdigest(),
        'sha256': hashlib.sha256(data).hexdigest()
    }


def add_scod_header(
    input_file: Path,
    output_file: Path,
    arch: int,
    force: bool = False,
    verify: bool = True
) -> None:
    """
    Adds SCOD header to shellcode
    
    Args:
        input_file: Path to input shellcode file
        output_file: Path to output file
        arch: Architecture (1=x86, 2=x64)
        force: Overwrite output file if exists
        verify: Verify result after writing
    """
    if not input_file.exists():
        raise FileNotFoundError(f"Input file not found: {input_file}")
    
    if not input_file.is_file():
        raise SCODHeaderError(f"Path is not a file: {input_file}")
    
    if output_file.exists() and not force:
        raise FileExistsError(
            f"Output file already exists: {output_file}\n"
            f"Use --force to overwrite"
        )
    
    logger.info(f"Reading shellcode from: {input_file}")
    try:
        shellcode = input_file.read_bytes()
    except Exception as e:
        raise SCODHeaderError(f"File read error: {e}")
    
    logger.info(f"Shellcode size: {len(shellcode)} bytes ({len(shellcode) / 1024:.2f} KB)")
    
    validator = ShellcodeValidator()
    
    validator.validate_size(shellcode)
    
    if validator.detect_existing_header(shellcode):
        logger.warning("Shellcode appears to already contain SCOD header!")
        if not force:
            raise SCODHeaderError(
                "Shellcode already contains SCOD header. "
                "Use --force to force adding"
            )
    
    is_valid, warning = validator.validate_shellcode_patterns(shellcode, arch)
    if warning:
        logger.warning(f"{warning}")
    
    header = SCODHeader(arch, len(shellcode))
    logger.info(f"Creating header for {'x64' if arch == 2 else 'x86'} architecture")
    
    final_data = header.to_bytes() + shellcode
    checksums = calculate_checksums(final_data)
    
    try:
        output_file.parent.mkdir(parents=True, exist_ok=True)
        output_file.write_bytes(final_data)
        logger.info(f"✓ File created: {output_file}")
    except Exception as e:
        raise SCODHeaderError(f"File write error: {e}")
    
    if verify:
        logger.info("Verifying created file...")
        try:
            verification_data = output_file.read_bytes()
            if verification_data != final_data:
                raise SCODHeaderError("Verification failed: data mismatch")
            
            verified_header = SCODHeader.from_bytes(verification_data)
            if verified_header.arch != arch or verified_header.length != len(shellcode):
                raise SCODHeaderError("Verification failed: header corrupted")
            
            logger.info("✓ Verification passed successfully")
        except Exception as e:
            output_file.unlink(missing_ok=True)
            raise SCODHeaderError(f"Verification failed: {e}")
    
    print("\n" + "="*50)
    print(header)
    print("="*50)
    print(f"Output file: {output_file}")
    print(f"Total size: {len(final_data)} bytes ({len(final_data) / 1024:.2f} KB)")
    print(f"\nChecksums:")
    print(f"  MD5:    {checksums['md5']}")
    print(f"  SHA1:   {checksums['sha1']}")
    print(f"  SHA256: {checksums['sha256']}")
    print("="*50)
    print(f"\n💉 For injection use:")
    print(f"   type {output_file.name} | injector.exe <target_process>")
    print(f"\n   Or in PowerShell:")
    print(f"   Get-Content {output_file.name} -Raw -Encoding Byte | .\\injector.exe <target_process>")


def main():
    """Main function"""
    parser = argparse.ArgumentParser(
        description='SCOD Header Tool - Adds header to shellcode for injector',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Usage examples:
  %(prog)s shellcode.bin output.bin x64
  %(prog)s shellcode.bin output.bin 2
  %(prog)s shellcode.bin output.bin x86 --force
  %(prog)s shellcode.bin output.bin 1 --no-verify
  
Supported architectures:
  x86, 32, 1 - for 32-bit processes
  x64, 64, 2 - for 64-bit processes
        """
    )
    
    parser.add_argument(
        'input',
        type=Path,
        help='Input file with shellcode from Donut or other generator'
    )
    
    parser.add_argument(
        'output',
        type=Path,
        help='Output file with added header'
    )
    
    parser.add_argument(
        'arch',
        type=str,
        help='Architecture: x86/x64/32/64/1/2'
    )
    
    parser.add_argument(
        '--force', '-f',
        action='store_true',
        help='Overwrite output file if exists'
    )
    
    parser.add_argument(
        '--no-verify',
        action='store_true',
        help='Do not verify result after writing'
    )
    
    parser.add_argument(
        '--verbose', '-v',
        action='store_true',
        help='Verbose output'
    )
    
    parser.add_argument(
        '--quiet', '-q',
        action='store_true',
        help='Minimal output errors only'
    )
    
    args = parser.parse_args()
    
    if args.quiet:
        logger.setLevel(logging.ERROR)
    elif args.verbose:
        logger.setLevel(logging.DEBUG)
    
    try:
        arch = parse_architecture(args.arch)
        add_scod_header(
            input_file=args.input,
            output_file=args.output,
            arch=arch,
            force=args.force,
            verify=not args.no_verify
        )
        
        logger.info("Operation completed successfully")
        return 0
        
    except KeyboardInterrupt:
        logger.error("\nInterrupted by user")
        return 130
        
    except (FileNotFoundError, FileExistsError) as e:
        logger.error(f" File error: {e}")
        return 1
        
    except SCODHeaderError as e:
        logger.error(f" Error: {e}")
        return 2
        
    except Exception as e:
        logger.error(f" Unexpected error: {e}")
        if args.verbose:
            import traceback
            traceback.print_exc()
        return 3


if __name__ == '__main__':
    sys.exit(main())