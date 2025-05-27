#!/usr/bin/env python3
"""
Dell Password Reset Emulator

A tool to extract and emulate Dell firmware password reset functionality
from UEFI firmware images.
"""

import argparse
import hashlib
import logging
import shutil
import struct
import sys
from os import listdir, mkdir, path
from pathlib import Path
from typing import Dict, List, Optional, Tuple, Generator, Any

import pefile
import uefi_firmware
from biosutilities.dell_pfs_extract import DellPfsExtract
from capstone import CS_GRP_CALL, CS_OP_MEM
from qiling import Qiling
from qiling.const import QL_VERBOSE, QL_ARCH, QL_OS


# GUID Constants
PWD_RESET_GUID = 'F2C68B35-9114-4528-AC75-5ADF2EBD6DAB'
PWD_RESET_GUID_BYTES = (
    b'\x35\x8b\xc6\xf2\x14\x91\x28\x45'
    b'\xac\x75\x5a\xdf\x2e\xbd\x6d\xab'
)

SECURITY_VAULT_GUID = 'C7CAF1C7-2D97-45CB-99D9-D89AAF8ACC11'
SECURITY_VAULT_GUID_BYTES = (
    b'\xc7\xf1\xca\xc7\x97\x2d\xcb\x45'
    b'\x99\xd9\xd8\x9a\xaf\x8a\xcc\x11'
)

LEGACY_SECURITY_VAULT_GUID = '119F3764-A7C2-4329-B25C-E6305E743049'
LEGACY_SECURITY_VAULT_GUID_BYTES = (
    b'\x64\x37\x9f\x11\xc2\xa7\x29\x43'
    b'\xb2\x5c\xe6\x30\x5e\x74\x30\x49'
)

class DellPasswordResetEmulator:
    """Main class for Dell password reset emulation."""
    
    def __init__(self, log_level: int = logging.INFO):
        """Initialize the emulator with logging configuration."""
        self.logger = self._setup_logging(log_level)
        
        # Emulation state
        self.ql_code_hook = None
        self.filled_servicetag = False
        self.emulated_reset_pwd = ""
        
    @staticmethod
    def _setup_logging(log_level: int) -> logging.Logger:
        """Set up logging configuration."""
        logger = logging.getLogger('dell_pwd_reset')
        logger.setLevel(log_level)
        
        if not logger.handlers:
            handler = logging.StreamHandler()
            formatter = logging.Formatter(
                '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
            )
            handler.setFormatter(formatter)
            logger.addHandler(handler)
            
        return logger

    @staticmethod
    def get_firmware_volumes(parent: Any) -> Generator[Any, None, None]:
        """Recursively extract firmware volumes from UEFI structures."""
        if isinstance(parent, uefi_firmware.uefi.FirmwareVolume):
            yield parent
        if hasattr(parent, 'objects'):
            for obj in parent.objects:
                yield from DellPasswordResetEmulator.get_firmware_volumes(obj)

    @staticmethod
    def get_firmware_filesystems(parent: Any) -> Generator[Any, None, None]:
        """Recursively extract firmware filesystems from UEFI structures."""
        if isinstance(parent, uefi_firmware.uefi.FirmwareFileSystem):
            yield parent
        if hasattr(parent, 'objects'):
            for obj in parent.objects:
                yield from DellPasswordResetEmulator.get_firmware_filesystems(obj)

    def parse_pfs_file(self, filename: str, extraction_path: str = "") -> Optional[str]:
        """Parse Dell PFS firmware file and extract contents."""
        self.logger.info(f"Attempting to parse {filename} as Dell PFS file")
        
        try:
            with open(filename, 'rb') as fw_file:
                fw_buffer = fw_file.read()
        except IOError as e:
            self.logger.error(f"Failed to read firmware file: {e}")
            return None

        output_path = extraction_path or f"{filename}_extracted"
        extractor = DellPfsExtract(fw_buffer, extract_path=output_path)
        
        if not extractor.check_format():
            self.logger.error("Unable to identify firmware format")
            return None
            
        try:
            Path(output_path).mkdir(mode=0o755, exist_ok=False)
        except FileExistsError:
            self.logger.error(f"Output path {output_path} already exists")
            return None
        except OSError as e:
            self.logger.error(f"Failed to create output directory: {e}")
            return None
            
        try:
            extractor.parse_format()
            self.logger.info(f"Successfully extracted firmware to {output_path}")
            return output_path
        except Exception as e:
            self.logger.error(f"Failed to parse firmware format: {e}")
            return None

    def parse_uefi_firmware(self, filename: str) -> Optional[Any]:
        """Parse UEFI firmware image."""
        try:
            with open(filename, 'rb') as fw_file:
                fw_buffer = fw_file.read()
        except IOError as e:
            self.logger.error(f"Failed to read UEFI firmware file: {e}")
            return None
            
        parser = uefi_firmware.AutoParser(fw_buffer)
        if parser.type() == 'UEFIFirmwareVolume':
            self.logger.info(f"Attempting to parse {filename} as UEFI Firmware image")
            return parser.parse()
        return None

    @staticmethod
    def guid_to_string(guid_bytes: bytes) -> str:
        """Convert GUID bytes to string representation."""
        d0, d1, d2 = struct.unpack('<LHH', guid_bytes[0:8])
        d3 = int.from_bytes(guid_bytes[8:10], byteorder="big")
        d4 = int.from_bytes(guid_bytes[10:], byteorder="big")
        return f'{d0:08X}-{d1:04X}-{d2:04X}-{d3:04X}-{d4:012X}'

    def scan_firmware_filesystems(self, firmware: Any, guid_bytes: bytes) -> List[Dict[str, Any]]:
        """Scan firmware filesystems for files matching the given GUID."""
        guid_str = self.guid_to_string(guid_bytes)
        self.logger.info(f"Scanning UEFI firmware filesystems for GUID {guid_str}")
        
        matching_files = []
        filesystems = list(self.get_firmware_filesystems(firmware))
        
        if not filesystems:
            self.logger.warning("No firmware file systems found in binary")
            return matching_files
            
        for filesystem in filesystems:
            for file_obj in filesystem.objects:
                if file_obj.guid == guid_bytes:
                    matching_files.append({
                        "filesystem": filesystem,
                        "file": file_obj,
                        "guid": guid_bytes
                    })
                    break
                    
        if not matching_files:
            self.logger.warning(f"No files found with GUID {guid_str}")
        else:
            self.logger.info(f"Found {len(matching_files)} matches for GUID {guid_str}")
            
        return matching_files

    @staticmethod
    def get_image_sections(firmware_file: Any) -> List[Any]:
        """Extract PE32 image sections from firmware file."""
        sections = []
        
        for section in firmware_file.objects:
            if section.attrs["type_name"] == "PE32 image":
                sections.append(section)
            elif section.attrs["type_name"] == "Compression":
                for subsection in section.parsed_object.subsections:
                    if subsection.attrs["type_name"] == "PE32 image":
                        sections.append(subsection)
                        
        return sections

    def find_validate_function(self, section_info: Dict[str, Any]) -> None:
        """Find the password validation function in the PE32 image."""
        image_data = section_info["section"].data
        
        try:
            pe = pefile.PE(data=image_data)
        except pefile.PEFormatError as e:
            self.logger.error(f"Failed to parse PE file: {e}")
            return
            
        reset_guid_offset = image_data.find(PWD_RESET_GUID_BYTES)
        
        if reset_guid_offset == -1:
            self.logger.warning("Password reset GUID not found in image")
            return
            
        try:
            base_adjust = pe.OPTIONAL_HEADER.ImageBase
            reset_guid_rva = pe.get_rva_from_offset(reset_guid_offset)
            
            # Navigate through pointer chain to find validation function
            p_reset_guid_rva = pe.get_rva_from_offset(
                image_data.find((base_adjust + reset_guid_rva).to_bytes(length=8, byteorder="little"))
            )
            pp_reset_guid_rva = pe.get_rva_from_offset(
                image_data.find((base_adjust + p_reset_guid_rva).to_bytes(length=8, byteorder="little"))
            )
            p_interface = pe.get_data(pp_reset_guid_rva + 0x10, 8)
            p_validate_fn = pe.get_data(
                int.from_bytes(p_interface, byteorder="little") + 0x10 - base_adjust, 8
            )
            
            section_info["validate_fn"] = int.from_bytes(p_validate_fn, byteorder="little") - base_adjust
            self.logger.info(f"Found password validate function at 0x{section_info['validate_fn']:x}")
            
        except (OverflowError, Exception) as e:
            self.logger.error(f"Unable to identify structure of security vault module: {e}")

    def emulate_password_interface(self, service_tag: str, device_key: int, 
                                 section_info: Dict[str, Any], root_path: str) -> str:
        """Emulate the password validation interface to generate reset password."""
        # Reset emulation state
        self.filled_servicetag = False
        self.emulated_reset_pwd = ""
        
        data = section_info["section"].data
        file_path = path.join(root_path, section_info["md5"])
        
        # Write PE data to file for Qiling
        try:
            with open(file_path, 'wb') as write_file:
                write_file.write(data)
        except IOError as e:
            self.logger.error(f"Failed to write PE file for emulation: {e}")
            return ""

        # Initialize Qiling emulator
        try:
            ql = Qiling(
                [file_path],
                rootfs=root_path,
                archtype=QL_ARCH.X8664,
                ostype=QL_OS.UEFI,
                verbose=QL_VERBOSE.OFF,
                profile='uefi.ql',
                log_plain=True
            )
        except Exception as e:
            self.logger.error(f"Failed to initialize Qiling emulator: {e}")
            return ""

        # Find image base address
        image_base = 0
        for memory_map in ql.mem.get_mapinfo():
            if memory_map[4] == file_path:
                image_base = memory_map[0]
                break

        # Set up emulation environment
        ql.arch.disassembler.detail = True
        start_address = image_base + section_info["validate_fn"]

        # Map memory for function arguments
        ql.arch.regs.write("R8", ql.mem.map_anywhere(0x10, minaddr=0x10000))
        buffer_size_va = ql.mem.map_anywhere(0x8, minaddr=0x10000)
        ql.mem.write(buffer_size_va, b'\x10\x00\x00\x00\x00\x00\x00\x00')
        ql.arch.regs.write("R9", buffer_size_va)

        # Set up code hooks
        context = {
            "servicetag": service_tag.encode('ascii'), 
            "devicekey": device_key,
            "emulator": self  # Pass self reference for state access
        }
        self.ql_code_hook = ql.hook_code(self._hook_branches, user_data=context)

        # Run emulation
        try:
            ql.run(begin=start_address)
            return self.emulated_reset_pwd
        except Exception as e:
            self.logger.error(f"Emulation failed: {e}")
            return ""

    def _print_password(self, ql: Qiling, context: int) -> None:
        """Hook function to capture generated password."""
        return_buffer = ql.mem.read(context, 16)
        ql.log.info(f"Password buffer: {return_buffer}")
        try:
            self.emulated_reset_pwd = return_buffer.decode('ascii').rstrip('\x00')
        except UnicodeDecodeError:
            self.emulated_reset_pwd = return_buffer.hex()
        ql.stop()

    def _hook_branches(self, ql: Qiling, address: int, size: int, context: Dict[str, Any]) -> None:
        """Hook function to handle branch instructions during emulation."""
        buffer = ql.mem.read(address, size)
        service_tag = context["servicetag"]
        device_key = context["devicekey"]

        for instruction in ql.arch.disassembler.disasm(buffer, address):
            if CS_GRP_CALL in instruction.groups:
                rcx = ql.arch.regs.read("RCX")
                
                if not self.filled_servicetag:
                    rdx = ql.arch.regs.read("RDX")
                    if rdx == 0x2618:
                        ql.log.info("Found PropertySmm Call to get service tag")
                        service_tag_va = ql.arch.stack_read(0x20)
                        ql.mem.write(service_tag_va, service_tag)
                        ql.log.info(f"Wrote service tag: {service_tag.decode('ascii')}")
                        ql.arch.regs.write("RIP", address + instruction.size)
                        self.filled_servicetag = True
                        
                elif ql.mem.is_mapped(rcx, 8):
                    drcx = ql.mem.read(rcx, len(service_tag))
                    if drcx == service_tag and ql.arch.regs.read("rdx") == len(service_tag):
                        ql.log.info(f"Found validate function @ 0x{address:x}")
                        
                        # Handle different firmware versions
                        arg5 = ql.arch.stack_read(0x20)
                        if arg5 != 1:
                            ql.arch.stack_write(0x20, device_key)
                            
                        return_buffer = ql.arch.regs.read("R8")
                        ql.hook_address(
                            self._print_password, 
                            address + instruction.size, 
                            user_data=return_buffer
                        )
                        ql.hook_del(self.ql_code_hook)
                        
                elif instruction.operands[0].type == CS_OP_MEM:
                    # Skip calls to unmapped memory
                    value = instruction.operands[0].value.mem
                    dest_address = 0
                    
                    if value.segment is not None:
                        dest_address += ql.arch.regs.read(value.segment)
                    dest_address += ql.arch.regs.read(value.base)
                    if value.index is not None:
                        dest_address += value.scale * ql.arch.regs.read(value.index)
                        
                    if not ql.mem.is_mapped(dest_address, 8):
                        ql.log.info(f"Skipping unmapped call at 0x{address:x}")
                        ql.arch.regs.write("RIP", address + instruction.size)

    @staticmethod
    def parse_device_string(device_string: str) -> Tuple[str, int]:
        """Parse device string in format XXXXXXX-YYYY to service tag and device ID."""
        if not device_string or len(device_string) != 12 or device_string[7] != '-':
            raise ValueError("Device string must be in format XXXXXXX-YYYY (7 chars, hyphen, 4 hex chars)")
        
        service_tag = device_string[:7]
        device_id_str = device_string[8:]
        
        # Validate service tag (alphanumeric)
        if not service_tag.isalnum():
            raise ValueError("Service tag must contain only alphanumeric characters")
        
        # Validate and convert device ID
        try:
            device_id = int(device_id_str, 16)
        except ValueError:
            raise ValueError("Device ID must be 4 hexadecimal characters")
            
        return service_tag, device_id

    def process_firmware(self, device_string: str, firmware_filename: str, 
                        delete_artifacts: bool = True) -> List[str]:
        """Main processing function to extract and emulate password reset."""
        # Parse and validate device string
        try:
            service_tag, device_id = self.parse_device_string(device_string)
        except ValueError as e:
            raise ValueError(f"Invalid device string: {e}")
        
        if not Path(firmware_filename).is_file():                                       
            raise FileNotFoundError(f"Firmware file {firmware_filename} does not exist")

        # Extract firmware
        extraction_path = self.parse_pfs_file(firmware_filename)
        if not extraction_path:
            return []

        try:
            firmware_path = path.join(extraction_path, 'Firmware')
            
            # Find SecurityVault modules
            modules = {}
            for filename in listdir(firmware_path):
                fw = self.parse_uefi_firmware(path.join(firmware_path, filename))
                if fw:
                    for guid_bytes in (SECURITY_VAULT_GUID_BYTES, LEGACY_SECURITY_VAULT_GUID_BYTES):
                        matches = self.scan_firmware_filesystems(fw, guid_bytes)
                        if matches:
                            modules[path.basename(filename)] = matches
                            break

            # Process modules and generate passwords
            results = []
            for module_matches in modules.values():
                for firmware_file in module_matches:
                    sections = self.get_image_sections(firmware_file["file"])
                    
                    for section in sections:
                        section_info = {
                            "section": section,
                            "md5": hashlib.md5(section.data).hexdigest()
                        }
                        
                        self.find_validate_function(section_info)
                        
                        if "validate_fn" in section_info:
                            result = self.emulate_password_interface(
                                service_tag, device_id, section_info, firmware_path
                            )
                            if result:
                                results.append(result)

            return results
            
        finally:
            if delete_artifacts and extraction_path:
                try:
                    shutil.rmtree(extraction_path)
                    self.logger.info(f"Cleaned up extraction directory: {extraction_path}")
                except OSError as e:
                    self.logger.warning(f"Failed to clean up extraction directory: {e}")


def main():
    """Main entry point with command-line interface."""
    parser = argparse.ArgumentParser(
        description="Dell Password Reset Emulator - Extract and emulate Dell firmware password reset functionality",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s ABCDEFG-1234 firmware.bin
  %(prog)s --verbose ABCDEFG-1234 firmware.bin
  %(prog)s --keep-artifacts ABCDEFG-1234 firmware.bin

Device String Format:
  - Format: XXXXXXX-YYYY
  - 7 alphanumeric characters for service tag
  - Hyphen separator
  - 4 hexadecimal characters for device ID

Note: This tool is for legitimate security research and authorized password recovery only.
        """)
    
    parser.add_argument(
        "device_string",
        help="Device string in format XXXXXXX-YYYY (7 chars for service tag, hyphen, 4 hex chars for device ID)"
    )
    
    parser.add_argument(
        "firmware_file",
        help="Path to Dell PFS firmware binary file"
    )
    
    parser.add_argument(
        "-v", "--verbose",
        action="store_true",
        help="Enable verbose logging"
    )
    
    parser.add_argument(
        "--keep-artifacts",
        action="store_true",
        help="Keep extracted firmware files after processing"
    )
    
    parser.add_argument(
        "--version",
        action="version",
        version="Dell Password Reset Emulator 1.0"
    )

    args = parser.parse_args()

    # Set up logging level
    log_level = logging.DEBUG if args.verbose else logging.INFO
    
    try:
        emulator = DellPasswordResetEmulator(log_level=log_level)
        
        results = emulator.process_firmware(
            args.device_string,
            args.firmware_file,
            delete_artifacts=not args.keep_artifacts
        )
        
        if results:
            print("\n" + "="*50)
            print("PASSWORD RESET RESULTS")
            print("="*50)
            for i, password in enumerate(results, 1):
                print(f"Reset Password {i}: {password}")
            print("="*50)
        else:
            print("No reset passwords generated. Check the firmware file and device string.")
            return 1
            
    except Exception as e:
        print(f"Error: {e}", file=sys.stderr)
        return 1
        
    return 0


if __name__ == "__main__":
    sys.exit(main())
