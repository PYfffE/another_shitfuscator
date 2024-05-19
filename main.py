import pwn

import shell_bytes

shellcode = shell_bytes.ShellBytes('./resources/instructions_hex.txt')

# shellcode.assemble('test.raw')

print(shellcode.get_payload())