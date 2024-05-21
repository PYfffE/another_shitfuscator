# import pwn

import shell_bytes

shellcode = shell_bytes.ShellBytes('./resources/instructions_hex.txt')

# shellcode.assemble('test.raw')

print('БЫЛО')
print('\n'.join(shellcode.get_payload()))
print()

shellcode.expand_offsets()

shellcode.add_prefix(['90', '90', '90'])
shellcode.add_postfix(['90', '90', '90'])

print('СТАЛО')
print('\n'.join(shellcode.get_payload()))

shellcode.compile('./resources/my_payload.raw')