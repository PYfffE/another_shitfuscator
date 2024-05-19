class ShellBytes:
    JUMPS_8_TO_32_CONVERT_OPCODES = {'7C': '0F 8C', '75': '0F 85',
                                     '74': '0F 84', '7E': '0F 8E',
                                     '7D': '0F 8D', 'EB': 'E9'}
    JUMPS_8_BIT_OPCODES = ['7C', '75', '74', '7E', '7D', 'EB', 'E2', 'E3']
    JUMPS_32_BIT_OPCODES = ['0F 8C', '0F 85', '0F 84', '0F 8E', '0F 8D', 'E9', 'E8']


    _disasm_shellcode = []
    _bytes_shellcode = []

    def _shellcode_to_bytes(self):
        self._bytes_shellcode = bytes.fromhex(''.join(i.replace(' ', '') for i in self._disasm_shellcode))
        return self._bytes_shellcode

    def __init__(self, disassemble_bytes_filename: str):
        self._disasm_shellcode = open(disassemble_bytes_filename, 'r').read().split('\n')
        self._shellcode_to_bytes()

    def get_payload(self):
        return self._disasm_shellcode.copy()

    def assemble(self, assemble_bytes_filename: str):
        if not self._disasm_shellcode:
            print('shellcode does not exist :(')
            return

        out_file = open(assemble_bytes_filename, 'wb')
        out_file.write(self._shellcode_to_bytes())
        out_file.close()

        print('shellcode created in file ', assemble_bytes_filename)


    # в changed_bytes хранится список измененных инструкций формата [bytes_number_didderence, index]
    def correct_offsets(self, changed_bytes: list):
        for changed_byte in changed_bytes:
            instr_i = 0
            while instr_i < len(self._disasm_shellcode):

                for opcode in self.JUMPS_8_BIT_OPCODES:
                    if self._disasm_shellcode[instr_i].startswith(opcode):
                        pass
                        break
                for opcode in self.JUMPS_32_BIT_OPCODES:
                    if self._disasm_shellcode[instr_i].startswith(opcode):
                        pass
                        break

                instr_i += 1


    def _change_instruction(self, new_instruction: bytes, instruction_index: int):
        pass


    def expand_offsets(self):
        pass


    # Добавить байт(ы)
    def insert(self, bytes_: bytes, byte_index):


