# import pwn

import shell_bytes

# Choose real or test payload
# shellcode = shell_bytes.ShellBytes('./resources/instructions_hex.txt')
shellcode = shell_bytes.ShellBytes('./resources/instructions_hex.txt')

# shellcode.assemble('test.raw')
#
print('БЫЛО')
print('\n'.join(shellcode.get_payload()))
print()

# shellcode.expand_offsets()

# shellcode.add_nops_after_each_instruction()
# shellcode.add_instruction('90', 10)

# shellcode.add_garbage_instructions_after_each_instruction('83 c0 46', '83 e8 46')

# shellcode.add_garbage_instructions_after_each_instruction_with_jmp()


# shellcode.add_prefix(['90', '90', '90'])
# shellcode.add_postfix(['90', '90', '90'])

print('СТАЛО')
print('\n'.join(shellcode.get_payload()))

shellcode.compile('./resources/my_payload.raw')