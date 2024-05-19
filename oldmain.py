# 0xffffffff = -1
# Отсчет смещения jmp начинается от первого байта следующей инструкции


hex_payload = open("resources/instructions_hex.txt", 'rb').read().decode('utf-8').split('\r\n')

# instructions with relative addresses (1 byte offset)
# jump_call_opcodes_8 = ['74', '7C', '75', 'FF', '7E', '7D']

# jecxz и loop не имеют rel32 аналогов

jmp_call_8_to_32 = {'7C': '0F 8C', '75': '0F 85', '74': '0F 84', '7E': '0F 8E', '7D': '0F 8D', 'EB': 'E9'}

jmp_32_opcodes = list(jmp_call_8_to_32.values())
jmp_32_opcodes.append('E8')

jmp_8_opcodes  = list(jmp_call_8_to_32.keys()  )
jmp_8_opcodes.append('E2')
jmp_8_opcodes.append('E3')

OFFSET_32_NEGATIVE = 2147483648
OFFSET_8_NEGATIVE = 128

additional_instr_list = []

offset_changes = {}

# example arg - "FE FF FF FF"
def hex_reverse(b: str):
    return ' '.join(list(reversed(b.split(' '))))


def add_prefix():
    hex_payload.insert(0, '90')
   
   
def add_postfix():
    hex_payload.insert(len(hex_payload), '90')
    
    
def add_offset_changes(instr_index: int, offset_num: int):
    if instr_index not in offset_changes.keys():
        offset_changes[instr_index] = offset_num
    else:
        offset_changes[instr_index] += offset_num


def add_nop_after_instr(after_opcode_index: int):
    hex_payload.insert(after_opcode_index + 1, '90')
    add_offset_changes(after_opcode_index, 1)


# example arg - "FE FF FF FF"
def hex_is_negative(hex_bytes: str):
    hex_bytes = hex_reverse(hex_bytes)
    if len(hex_bytes) == 2:
        if int(hex_bytes, 16) >= OFFSET_8_NEGATIVE:
            return 1
        else:
            return 0
    elif len(hex_bytes.replace(' ','')) == 8:
        if int(hex_bytes.replace(' ', ''), 16) >= OFFSET_32_NEGATIVE:
            return 1
        else:
            return 0
    else:
        print('hex_is_negative BRUH')
        print(hex_bytes)
        exit(1)


def int_to_hex_with_spaces(num: int, size = 4):
    if size == 1:
        if 0 <= num < 256:
            return f'{num:x}'.upper()
        elif -256 < num < 0:
            neg_num = ((num + (1 << 8)) % (1 << 8))
            return f'{neg_num:x}'.upper()
        else:
            print('int_to_hex_with_spaces BRUH')
            exit(1)
    elif size == 4:
        if 0 <= num < 2**32:
            str_hex = "{0:0{1}x}".format(num, 8)
            return hex_reverse(' '.join(str_hex[i:i+2] for i in range(0, len(str_hex), 2))).upper()
        elif -(2**32) < num < 0:
            neg_num = ((num + (1 << 32)) % (1 << 32))
            str_hex = f'{neg_num:x}'
            return  hex_reverse(' '.join(str_hex[i:i+2] for i in range(0, len(str_hex), 2)).upper())
        else:
            print('int_to_hex_with_spaces BRUH')
            exit(1)
    else:
        print('int_to_hex_with_spaces BRUH')
        exit(1)
            

def fix_offsets():
    i = 0
    while i < len(additional_instr_list):

        j = 0
        while j < len(jmp_32_opcodes):
            if additional_instr_list[i][0].startswith(jmp_32_opcodes[j]):
                offset = additional_instr_list[i][0][-11:]
                if hex_is_negative(offset) == 0:
                    int_offset = int.from_bytes(bytes.fromhex(hex_reverse(offset).replace(' ', '')), "big")
                    print(additional_instr_list[i][0])
                    print('было  ' + jmp_32_opcodes[j] + ' ' + int_to_hex_with_spaces(int_offset))
                    base_i = i + 1
                    base_l = base_i + int_offset
                    base_real = base_i
                    while base_real < base_l:
                        opcodes_num = len(ORIG_additional_instr_list[base_i][0].split(' '))
                        base_real += opcodes_num
                        if additional_instr_list[i][0] == 'E3 48':
                            print('333 ' + str(ORIG_additional_instr_list[base_i]))
                        if additional_instr_list[base_i][1] > 0:
                            if additional_instr_list[i][0] == 'E3 48':
                                print('222 ' + str(ORIG_additional_instr_list[base_i][1]))
                            int_offset += additional_instr_list[base_i][1]
                        base_i += 1
                    print('Стало ' + jmp_32_opcodes[j] + ' ' + int_to_hex_with_spaces(int_offset))
                    additional_instr_list[i][0] = jmp_32_opcodes[j] + ' ' + int_to_hex_with_spaces(int_offset)
                    # int_to_hex_with_spaces()
                    
                else:
                    int_offset = - (2**32 - int.from_bytes(bytes.fromhex(hex_reverse(offset).replace(' ', '')), "big"))
                    print(additional_instr_list[i][0])
                    print('было  ' + jmp_32_opcodes[j] + ' ' + int_to_hex_with_spaces(int_offset))
                    base_i = i + 1
                    base_l = base_i + int_offset
                    base_real = base_i
                    while base_real >= base_l:
                        if additional_instr_list[i][0] == '0F 85 F6 FF FF FF':
                            print('11111111 ' + str(additional_instr_list[base_i]))
                        opcodes_num = len(ORIG_additional_instr_list[base_i][0].split(' '))
                        base_real -= opcodes_num
                        if additional_instr_list[base_i][1] > 0:
                            int_offset -= additional_instr_list[base_i][1]
                        base_i -= 1
                    # print(additional_instr_list[i][0])
                    # print(hex(base_i) + ' - ' + hex(base_l)) 
                    print('Стало ' + jmp_32_opcodes[j] + ' ' + int_to_hex_with_spaces(int_offset))
                    additional_instr_list[i][0] = jmp_32_opcodes[j] + ' ' + int_to_hex_with_spaces(int_offset)
                print()
                break
            j += 1
        # with 8 bit offsets
        j = 0
        while j < len(jmp_8_opcodes):
            
            if additional_instr_list[i][0].startswith(jmp_8_opcodes[j]):
                
                offset = additional_instr_list[i][0][-2:]
                if hex_is_negative(offset) == 0:
                    int_offset = int.from_bytes(bytes.fromhex(hex_reverse(offset).replace(' ', '')), "big")
                    print(additional_instr_list[i][0])
                    print('было  ' + jmp_8_opcodes[j] + ' ' + int_to_hex_with_spaces(int_offset, 1))
                    base_i = i + 1
                    base_l = base_i + int_offset
                    base_real = base_i
                    while base_real < base_l:
                            # print(base_real)
                            
                        opcodes_num = len(ORIG_additional_instr_list[base_i][0].split(' '))
                        base_real += opcodes_num
                        
                        if additional_instr_list[base_i][1] > 0:
                            # print(additional_instr_list[base_i][0])
                            # print(additional_instr_list[base_i][1])
                            int_offset += additional_instr_list[base_i][1]
                        base_i += 1
                    print('Стало ' +  jmp_8_opcodes[j] + ' ' + int_to_hex_with_spaces(int_offset, 1))
                    additional_instr_list[i][0] = jmp_8_opcodes[j] + ' ' + int_to_hex_with_spaces(int_offset, 1)
                    # int_to_hex_with_spaces()
                    
                else:
                    int_offset = - (256 - int.from_bytes(bytes.fromhex(hex_reverse(offset).replace(' ', '')), "big"))
                    print(additional_instr_list[i][0])
                    print('было  ' + jmp_8_opcodes[j] + ' ' + int_to_hex_with_spaces(int_offset, 1))
                    base_i = i + 1 
                    base_l = base_i + int_offset
                    base_real = base_i
                    while base_real >= base_l:
                        
                        opcodes_num = len(ORIG_additional_instr_list[base_i][0].split(' '))
                        base_real -= opcodes_num
                        if additional_instr_list[base_i][1] > 0:
                            int_offset -= additional_instr_list[base_i][1]
                        base_i -= 1
                    # print(additional_instr_list[i][0])
                    # print(hex(base_i) + ' - ' + hex(base_l)) 
                    print('Стало ' + jmp_8_opcodes[j] + ' ' + int_to_hex_with_spaces(int_offset, 1))
                    additional_instr_list[i][0] = jmp_8_opcodes[j] + ' ' + int_to_hex_with_spaces(int_offset, 1)
                print()
                break
            j += 1
        i += 1


def null_new_bytes():
    i = 0
    while i < len(additional_instr_list):
        additional_instr_list[i][1] = 0
        i += 1


def obfuscate():
    global additional_instr_list
    global ORIG_additional_instr_list
    additional_instr_list = [[i.upper(), 0] for i in hex_payload]
    ORIG_additional_instr_list = [[j for j in i] for i in additional_instr_list]
    # print(ORIG_additional_instr_list)
    
    # i = 0
    # while i < len(hex_payload):
    #     add_nop_after_instr(i)
    #     i += 2
    
    # 1. Заменить 8-битные jmp на 32
    i = 0
    while i < len(additional_instr_list):
        instr_opcode = additional_instr_list[i][0][0:2]
        if instr_opcode in jmp_call_8_to_32.keys():
            # Расширение размера смещений
            # print(additional_instr_list[i][0])
            negative_test = hex_is_negative(additional_instr_list[i][0][3:])
            if negative_test == 1:
                additional_instr_list[i][0] += ' FF FF FF'
                additional_instr_list[i][1] += 3
                ORIG_additional_instr_list[i][1] += 3
            else:
                additional_instr_list[i][0] += ' 00 00 00'
                additional_instr_list[i][1] += 3
                ORIG_additional_instr_list[i][1] += 3
            
            # Замена опкодов jmp-like команд
            additional_instr_list[i][0] = additional_instr_list[i][0].replace(instr_opcode, jmp_call_8_to_32[instr_opcode])
            additional_instr_list[i][1] += len(jmp_call_8_to_32[instr_opcode].split(' ')) - 1
            ORIG_additional_instr_list[i][1] += len(jmp_call_8_to_32[instr_opcode].split(' ')) - 1
            
            
            
            # print('- ' + additional_instr_list[i][0])

        i += 1
            
    # print(additional_instr_list)
    # exit()
               
    # 2. Исправляем адреса из-за изменений jmp
    fix_offsets()
    print(additional_instr_list)
  
    # 2.2 Обнулить добавляемые байты
    null_new_bytes()
    
    # 3. добавляем мусорные коменда
    for i in additional_instr_list:
        i[1] = 0
    
    # 4. правим адреса
    for i in additional_instr_list:
        pass
    
    # 4.2 Обнуляем
        

    # add_prefix()
    # add_postfix()

def compile():
    with open("resources/my_payload.raw", "wb") as f:
        for i in additional_instr_list:
            one_instruction = bytes.fromhex(i[0].replace(' ',''))
            f.write(one_instruction)

obfuscate()

# print(offset_changes)
# print(hex_payload)

compile()