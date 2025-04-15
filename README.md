# artd-Binary-Diff-Tool
Compares two binary files and highlights the differences in their assembly code, facilitating vulnerability analysis and patch diffing. - Focused on Analyzes and disassembles compiled artifacts (e.g., ELF, PE, Mach-O) to identify potential vulnerabilities, embedded payloads, or hidden functionality. Leverages disassembly and parsing libraries to extract and present meaningful information about the artifact's structure and code execution flow.

## Install
`git clone https://github.com/ShadowStrikeHQ/artd-binary-diff-tool`

## Usage
`./artd-binary-diff-tool [params]`

## Parameters
- `-h`: Show help message and exit
- `-a`: No description provided
- `-o`: Output file to save the diff results. If not provided, prints to console.
- `-v`: Enable verbose logging.

## License
Copyright (c) ShadowStrikeHQ
