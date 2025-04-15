#!/usr/bin/env python3

import argparse
import lief
import capstone
import logging
import sys
import os

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

def setup_argparse():
    """
    Sets up the argument parser for the command-line interface.
    Returns:
        argparse.ArgumentParser: The argument parser object.
    """
    parser = argparse.ArgumentParser(description="Compares two binary files and highlights the differences in their assembly code.")
    parser.add_argument("file1", help="The first binary file to compare.")
    parser.add_argument("file2", help="The second binary file to compare.")
    parser.add_argument("-a", "--architecture", choices=['x86', 'x64', 'arm', 'arm64'], default='x86',
                        help="The architecture of the binary files (default: x86).")
    parser.add_argument("-o", "--output", help="Output file to save the diff results. If not provided, prints to console.", default=None)
    parser.add_argument("-v", "--verbose", action="store_true", help="Enable verbose logging.")
    return parser

def disassemble(file_path, arch):
    """
    Disassembles a binary file using LIEF and Capstone.

    Args:
        file_path (str): The path to the binary file.
        arch (str): The architecture of the binary ("x86", "x64", "arm", "arm64").

    Returns:
        dict: A dictionary where keys are addresses and values are assembly instructions.
              Returns None on error.
    """
    try:
        binary = lief.parse(file_path)
        if binary is None:
            logging.error(f"Failed to parse {file_path} with LIEF.")
            return None

        if arch == 'x86':
            md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_32)
        elif arch == 'x64':
            md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
        elif arch == 'arm':
            md = capstone.Cs(capstone.CS_ARCH_ARM, capstone.CS_MODE_ARM)
        elif arch == 'arm64':
            md = capstone.Cs(capstone.CS_ARCH_ARM64, capstone.CS_MODE_ARM)
        else:
            logging.error(f"Unsupported architecture: {arch}")
            return None

        disassembly = {}
        for section in binary.sections:
            if section.has_characteristic(lief.ELF.SECTION_FLAGS.EXECUTE):
                logging.info(f"Disassembling section: {section.name}")
                for i in md.disasm(section.content, section.virtual_address):
                    disassembly[i.address] = i.mnemonic + " " + i.op_str

        return disassembly

    except lief.bad_file as e:
        logging.error(f"LIEF Error parsing {file_path}: {e}")
        return None
    except Exception as e:
        logging.error(f"Error disassembling {file_path}: {e}")
        return None


def diff_assemblies(assembly1, assembly2):
    """
    Compares two disassembled binaries and identifies differences.

    Args:
        assembly1 (dict): The disassembly of the first binary.
        assembly2 (dict): The disassembly of the second binary.

    Returns:
        dict: A dictionary containing the differences between the two assemblies.
              Keys: 'added', 'removed', 'modified'
    """
    added = {}
    removed = {}
    modified = {}

    for addr, instruction in assembly2.items():
        if addr not in assembly1:
            added[addr] = instruction

    for addr, instruction in assembly1.items():
        if addr not in assembly2:
            removed[addr] = instruction
        elif assembly2[addr] != instruction:
            modified[addr] = (instruction, assembly2[addr])  # (original, modified)

    return {'added': added, 'removed': removed, 'modified': modified}


def validate_file(file_path):
    """
    Validates if the provided file path exists and is a file.

    Args:
        file_path (str): The path to the file.

    Returns:
        bool: True if the file is valid, False otherwise.
    """
    if not os.path.exists(file_path):
        logging.error(f"Error: File not found: {file_path}")
        return False
    if not os.path.isfile(file_path):
        logging.error(f"Error: Not a file: {file_path}")
        return False
    return True


def write_diff_to_file(diff, output_file):
    """
    Writes the disassembly differences to a file.

    Args:
        diff (dict): The dictionary of differences.
        output_file (str): The path to the output file.
    """
    try:
        with open(output_file, "w") as f:
            f.write("Added instructions:\n")
            for addr, instruction in diff['added'].items():
                f.write(f"  0x{addr:x}: {instruction}\n")

            f.write("\nRemoved instructions:\n")
            for addr, instruction in diff['removed'].items():
                f.write(f"  0x{addr:x}: {instruction}\n")

            f.write("\nModified instructions:\n")
            for addr, (original, modified) in diff['modified'].items():
                f.write(f"  0x{addr:x}: Original: {original} | Modified: {modified}\n")

        logging.info(f"Diff written to {output_file}")
    except Exception as e:
        logging.error(f"Error writing diff to file: {e}")


def print_diff_to_console(diff):
    """
    Prints the disassembly differences to the console.

    Args:
        diff (dict): The dictionary of differences.
    """
    print("Added instructions:")
    for addr, instruction in diff['added'].items():
        print(f"  0x{addr:x}: {instruction}")

    print("\nRemoved instructions:")
    for addr, instruction in diff['removed'].items():
        print(f"  0x{addr:x}: {instruction}")

    print("\nModified instructions:")
    for addr, (original, modified) in diff['modified'].items():
        print(f"  0x{addr:x}: Original: {original} | Modified: {modified}")


def main():
    """
    Main function to orchestrate the binary diffing process.
    """
    parser = setup_argparse()
    args = parser.parse_args()

    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)

    # Input validation
    if not validate_file(args.file1):
        sys.exit(1)
    if not validate_file(args.file2):
        sys.exit(1)

    try:
        # Disassemble the binary files
        logging.info(f"Disassembling {args.file1}...")
        assembly1 = disassemble(args.file1, args.architecture)
        if assembly1 is None:
            sys.exit(1)

        logging.info(f"Disassembling {args.file2}...")
        assembly2 = disassemble(args.file2, args.architecture)
        if assembly2 is None:
            sys.exit(1)


        # Compare the assemblies
        logging.info("Comparing assemblies...")
        diff = diff_assemblies(assembly1, assembly2)

        # Output the diff
        if args.output:
            write_diff_to_file(diff, args.output)
        else:
            print_diff_to_console(diff)

        logging.info("Binary diff completed.")

    except Exception as e:
        logging.error(f"An unexpected error occurred: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()

# Usage Examples:
# 1. Compare two binaries and print the diff to the console:
#    python artd_binary_diff_tool.py file1.bin file2.bin
#
# 2. Compare two binaries with x64 architecture and save the diff to a file:
#    python artd_binary_diff_tool.py file1.bin file2.bin -a x64 -o diff.txt
#
# 3. Enable verbose logging:
#    python artd_binary_diff_tool.py file1.bin file2.bin -v