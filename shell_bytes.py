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

    def check_and_fix_offset(self, jmp_index):
        pass

    @staticmethod
    def str_hex_reverse(str_hex: str):
        return ' '.join(list(reversed(str_hex.split(' '))))

    def offset_str_int_to_hex(self, int_hex: int, offset_size: int):
        if offset_size not in [8, 32]:
            raise SystemExit('offset_str_int_to_hex bruh')

        str_hex = f'{((int_hex + (1 << offset_size)) % (1 << offset_size)):x}'

        if offset_size == 8:
            return str_hex.upper()

        elif offset_size == 32:
            return self.str_hex_reverse(' '.join(str_hex[i:i + 2] for i in range(0, len(str_hex), 2)).upper())

    def offset_str_hex_to_int(self, str_hex: str):

        reverse_str_hex = self.str_hex_reverse(str_hex)

        int_hex = int(reverse_str_hex.replace(' ', ''), 16)
        if len(reverse_str_hex) == 2:

            if 0 <= int_hex < 128:
                return int_hex
            elif 128 <= int_hex < 256:
                return 256 - int_hex
            else:
                raise SystemExit('offset_str_hex_to_int bruh')

        elif len(reverse_str_hex) == 11:
            if 0 <= int_hex < 2**31:
                return int_hex
            elif 2**31 <= int_hex < 2**32:
                return 2**32 - int_hex
        else:
            raise SystemExit('offset_str_hex_to_int bruh')


    # в changed_bytes хранится список измененных инструкций формата [bytes_number_didderence, index]
    def _fix_all_offsets(self, changed_bytes: list):
        for changed_byte in changed_bytes:
            instr_i = 0
            while instr_i < len(self._disasm_shellcode):

                for opcode in self.JUMPS_8_BIT_OPCODES:
                    if self._disasm_shellcode[instr_i].startswith(opcode):
                        start_i = instr_i + 1
                        int_offset = self.offset_str_hex_to_int(self._disasm_shellcode[instr_i][-2:])
                        dest_i = start_i + int_offset
                        if dest_i - start_i >= 0:
                            pass
                        else:
                            pass



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
        pass


