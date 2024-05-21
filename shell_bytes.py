from random import randrange


class ShellBytes:
    JUMPS_8_TO_32_CONVERT_OPCODES = {'7C': '0F 8C', '75': '0F 85',
                                     '74': '0F 84', '7E': '0F 8E',
                                     '7D': '0F 8D', 'EB': 'E9'}
    JUMPS_8_BIT_OPCODES = ['7C', '75', '74', '7E', '7D', 'EB', 'E2', 'E3']
    JUMPS_32_BIT_OPCODES = ['0F 8C', '0F 85', '0F 84', '0F 8E', '0F 8D', 'E9', 'E8']
    changes_buf = {}

    _disasm_shellcode = []
    _bytes_shellcode = []

    def _shellcode_to_bytes(self):
        self._bytes_shellcode = bytes.fromhex(''.join(i.replace(' ', '') for i in self._disasm_shellcode))
        return self._bytes_shellcode

    def __init__(self, disassemble_bytes_filename: str):
        self._disasm_shellcode = [i.upper() for i in open(disassemble_bytes_filename, 'r').read().split('\n')]
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

    @staticmethod
    def str_hex_reverse(str_hex: str):

        return ' '.join(list(reversed(str_hex.split(' '))))

    def offset_int_to_str_hex(self, int_hex: int, offset_size: int):
        if offset_size not in [8, 32]:
            raise SystemExit('offset_str_int_to_hex bruh')
        str_hex = f'{((int_hex + (1 << offset_size)) % (1 << offset_size)):0{int(offset_size / 8) * 2}x}'

        # Проверка на переполнение
        # Возможно работает через попу
        if not (-(2 ** (offset_size - 1))) <= int_hex < (2 ** (offset_size - 1)):
            return None

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
                return - (256 - int_hex)
            else:
                raise SystemExit('offset_str_hex_to_int bruh')

        elif len(reverse_str_hex) == 11:
            if 0 <= int_hex < 2 ** 31:
                return int_hex
            elif 2 ** 31 <= int_hex < 2 ** 32:
                return - (2 ** 32 - int_hex)
        else:
            raise SystemExit('offset_str_hex_to_int bruh')

    def _get_offset(self, hex_instr: str):
        for opcode in self.JUMPS_8_BIT_OPCODES:
            if hex_instr.startswith(opcode):
                return hex_instr[-2:], 8, opcode
        for opcode in self.JUMPS_32_BIT_OPCODES:
            if hex_instr.startswith(opcode):
                return hex_instr[-11:], 32, opcode
        return None, None, None

    def _fix_offset(self, jmp_index: int, offset_of_offset: int):
        hex_offset, offset_size, instr_opcode = self._get_offset(self._disasm_shellcode[jmp_index])
        int_offset = self.offset_str_hex_to_int(hex_offset)

        offset_changes = int_offset + offset_of_offset

        # Проверка на переполнение
        # Работает через попу
        if (offset_changes < 0) and (not ((- (2 ** (offset_size - 1))) <= offset_changes)):
            return False
        elif (offset_changes > 0) and (not ((2 ** (offset_size - 1)) > offset_changes)):
            return False
        # if not ((- (2 ** (offset_size - 1))) <= offset_changes < (2 ** (offset_size - 1))):
        #     return False

        self._disasm_shellcode[jmp_index] = instr_opcode + ' ' + self.offset_int_to_str_hex(offset_changes, offset_size)
        self._shellcode_to_bytes()
        return True

    def get_real_index(self, instr_index):
        real_index = 0
        i = 0
        while i < instr_index:
            if i in self.changes_buf.keys():
                real_index += self.changes_buf[i]
            else:
                real_index += len(self._disasm_shellcode[i].split(' '))
            i += 1
        return real_index

    # в changed_bytes хранится структура (словарь) с измененной инструкцей формата {'bytes_number_difference': 1,
    #                                                                                                  index: 10}
    def _fix_all_offsets(self, changed_bytes: dict):

        instr_i = 0

        while instr_i < len(self._disasm_shellcode):
            hex_offset, offset_size, hex_opcode = self._get_offset(self._disasm_shellcode[instr_i])
            if offset_size:
                start_i = instr_i + 1
                int_offset = self.offset_str_hex_to_int(hex_offset)
                # dest_i = start_i + int_offset

                dest_i = 0
                if instr_i == 1:
                    asd = 1

                if hex_opcode == 'E2':
                    asd = 1

                real_start_index = self.get_real_index(start_i)
                real_dest_index = real_start_index + int_offset
                real_changed_index = self.get_real_index(changed_bytes['index'])

                if (real_start_index <= real_changed_index < real_dest_index) or (
                        real_dest_index <= real_changed_index < real_start_index):
                    test = True
                    if int_offset >= 0:
                        test = self._fix_offset(instr_i, changed_bytes['bytes_number_difference'])
                    else:
                        test = self._fix_offset(instr_i, - changed_bytes['bytes_number_difference'])

                    if not test:
                        print('Cannot change offset because overflow offset ' + self._disasm_shellcode[
                            instr_i] + ' overflow with number ' + str(
                            changed_bytes['bytes_number_difference']) + '. Skipped')

                        return False

                    if instr_i in self.changes_buf.keys():
                        del self.changes_buf[instr_i]

            instr_i += 1
        return True

    def _change_instruction(self, instruction_index: int, new_instruction: bytes):
        str_hex = new_instruction.hex()
        self._disasm_shellcode[instruction_index] = ' '.join(
            str_hex[i:i + 2] for i in range(0, len(str_hex), 2)).upper()
        self._shellcode_to_bytes()
        pass

    def add_instruction(self, hex_str: str, after_index: int):
        self._disasm_shellcode.insert(after_index + 1, hex_str)
        self._shellcode_to_bytes()
        test = self._fix_all_offsets({'bytes_number_difference': len(hex_str.split(' ')), 'index': after_index + 1})
        self.changes_buf = {}
        return test

    def _get_opcode_size(self, str_hex: str):
        return len(str_hex.split(' '))

    def expand_offsets(self):
        array_of_changes = []
        instr_i = 0
        while instr_i < len(self._disasm_shellcode):
            jmp_offset, offset_size, opcode = self._get_offset(self._disasm_shellcode[instr_i])
            if opcode in self.JUMPS_8_TO_32_CONVERT_OPCODES.keys():

                current_size = self._get_opcode_size(self._disasm_shellcode[instr_i])
                new_instr = self.JUMPS_8_TO_32_CONVERT_OPCODES[opcode] + ' ' + self.offset_int_to_str_hex(
                    self.offset_str_hex_to_int(jmp_offset), 32)

                new_size = self._get_opcode_size(new_instr)

                self._change_instruction(instr_i, bytes.fromhex(new_instr.replace(' ', '')))
                array_of_changes.append({'bytes_number_difference': new_size - current_size, 'index': instr_i})
                self.changes_buf[instr_i] = current_size
            instr_i += 1

        for change_i in array_of_changes:
            self._fix_all_offsets(change_i)
        self.changes_buf = {}

    # @param hex_commands: example ['90', '90', '90']
    def add_prefix(self, hex_commands: list):
        revert_i = len(hex_commands) - 1
        while revert_i >= 0:
            self._disasm_shellcode.insert(0, hex_commands[revert_i])
            revert_i -= 1
        self._shellcode_to_bytes()

    # @param hex_commands: example ['90', '90', '90']
    def add_postfix(self, hex_commands: list):
        instr_i = 0
        while instr_i < len(hex_commands):
            self._disasm_shellcode.insert(len(self._disasm_shellcode) + 1, hex_commands[instr_i])
            instr_i += 1
        self._shellcode_to_bytes()

    def add_garbage_instructions_after_each_instruction(self, str_hex_instruction1: str, str_hex_instruction2: str):
        instr_i = 0
        while instr_i < len(self._disasm_shellcode):
            self.add_instruction(str_hex_instruction1, instr_i)
            instr_i += 1
            self.add_instruction(str_hex_instruction2, instr_i)
            # self.add_instruction('EB 04 ' + f' {randrange(17):0{2}x} ' + f' {randrange(17):0{2}x} ' + f' {randrange(17):0{2}x} ' + f' {randrange(17):0{2}x}', instr_i)
            instr_i += 1
            instr_i += 1

    # Not Working! :(
    def add_garbage_instructions_after_each_instruction_with_jmp(self):
        instr_i = 0
        while instr_i < len(self._disasm_shellcode):
            copy_buf = self._disasm_shellcode.copy()
            copy_i = instr_i

            test1 = True
            test2 = True

            test1 = self.add_instruction('EB 04', instr_i)
            if test1:
                instr_i += 1
                test2 = self.add_instruction('90 90 90 90', instr_i)
                if test2:
                    instr_i += 1
                    self._disasm_shellcode[instr_i - 1] = 'EB 04'
            if not (test1 and test2):
                instr_i = copy_i
                self._disasm_shellcode = copy_buf.copy()

            instr_i += 1

    def add_nops_after_each_instruction(self):
        instr_i = 0
        while instr_i < len(self._disasm_shellcode):
            self.add_instruction('90', instr_i)
            # self.add_instruction('EB 04 ' + f' {randrange(17):0{2}x} ' + f' {randrange(17):0{2}x} ' + f' {randrange(17):0{2}x} ' + f' {randrange(17):0{2}x}', instr_i)
            instr_i += 1
            instr_i += 1

    def compile(self, out_filename):
        with open(out_filename, "wb") as f:
            for i in self._disasm_shellcode:
                one_instruction = bytes.fromhex(i.replace(' ', ''))
                f.write(one_instruction)
        print('Payload writed in ', out_filename)
