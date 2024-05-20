# import pwn

import shell_bytes

shellcode = shell_bytes.ShellBytes('./resources/instructions_hex.txt')

# shellcode.assemble('test.raw')

print('БЫЛО')
print('\n'.join(shellcode.get_payload()))
print()

shellcode.expand_offsets()

print('СТАЛО')
print('\n'.join(shellcode.get_payload()))

shellcode.compile('./resources/my_payload.raw')