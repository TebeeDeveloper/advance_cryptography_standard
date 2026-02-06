import os
import sys
import time
import shlex
from tbcryptography import TBAEMS 
from colorama import Fore, Back, Style, init

# Khởi tạo colorama
init(autoreset=True)

class Ter:
    def __init__(self) -> None:
        # Prompt: aems> màu Green, sau đó reset để user nhập màu White
        self.prompt: str = f"{Fore.GREEN}aems> {Fore.WHITE}"
        self.aems: TBAEMS | None = None 
        self.current_key: bytes | None = None

    def run(self) -> None:
        self._run_load_(5, "INITIALIZING SYSTEM") # Giảm thời gian load cho bớt sốt ruột nhé
        while True:
            try:
                # Dùng shlex.split để xử lý chuỗi có dấu cách chuẩn xác
                cmd_line = input(self.prompt).strip()
                if not cmd_line: continue
                
                parts = shlex.split(cmd_line)
                command = parts[0].lower()
                args = parts[1:]

                match command:
                    case "help" | "/help":
                        self.show_help()

                    case "exit" | "quit":
                        print(f"{Fore.YELLOW}[System]: Shutting down...")
                        break

                    case "create":
                        if "--new" in args:
                            self.current_key = TBAEMS.generate_key_256()
                            self.aems = TBAEMS(self.current_key)
                            print(f"{Fore.CYAN}[System]: New Key generated: {Fore.WHITE}{self.current_key.hex()}\n")
                        elif "--key" in args:
                            try:
                                idx = args.index("--key") + 1
                                self.current_key = bytes.fromhex(args[idx])
                                self.aems = TBAEMS(self.current_key)
                                print(f"{Fore.CYAN}[System]: Key loaded successfully.\n")
                            except (ValueError, IndexError):
                                print(f"{Fore.RED}[Error]: Invalid Hex format or missing key!\n")
                        else:
                            print(f"{Fore.YELLOW}[System]: Unknown Command. Type 'help'\n")

                    case "encrypt":
                        if not self._check_ready(): continue
                        
                        if "-t" in args:
                            # Tương tự terminal.py: lấy tất cả sau -t
                            start_idx = args.index("-t") + 1
                            text_to_encrypt = " ".join(args[start_idx:])
                            
                            if not text_to_encrypt:
                                print(f"{Fore.RED}[Error]: Nothing to encrypt!\n")
                                continue
                                
                            print(f"{Fore.GREEN}[Encrypted]: {Fore.WHITE}{self.encrypt_text(text_to_encrypt)}\n")

                        elif "-f" in args:
                            idx = args.index("-f") + 1
                            filepath = args[idx]
                            if os.path.exists(filepath):
                                out_path = filepath + ".aems"
                                self.encrypt_file_with_magic(filepath, out_path)
                                print(f"{Fore.YELLOW}[System]: File saved: {Fore.WHITE}{out_path}\n")
                            else:
                                print(f"{Fore.RED}[Error]: File Not Found: {filepath}\n")

                    case "decrypt":
                        if not self._check_ready(): continue
                        
                        if "-t" in args:
                            try:
                                idx = args.index("-t") + 1
                                encrypted_str = args[idx]
                                decrypted = self.decrypt_text(encrypted_str)
                                print(f"{Fore.GREEN}[Decrypted]: {Fore.WHITE}{decrypted}\n")
                            except Exception as e:
                                print(f"{Fore.RED}[Error]: Decryption failed. Check your data and key!\n")

                        elif "-f" in args:
                            idx = args.index("-f") + 1
                            filepath = args[idx]
                            if os.path.exists(filepath):
                                out_path = filepath.replace(".aems", ".txt")
                                self.decrypt_file_with_magic(filepath, out_path)
                                print(f"{Fore.YELLOW}[System]: File restored to: {Fore.WHITE}{out_path}\n")
                            else:
                                print(f"{Fore.RED}[Error]: File Not Found\n")

                    case _:
                        print(f"{Fore.YELLOW}[System]: Unknown Command. Type 'help'\n")

            except KeyboardInterrupt:
                print(f"\n{Fore.YELLOW}[System]: Interrupted. Closing...\n")
                break
            except Exception as e:
                print(f"{Fore.RED}[Runtime Error]: {e}\n")

    def _check_ready(self) -> bool:
        if not self.aems:
            print(f"{Fore.RED}[Error]: Engine not initialized. Run 'create --new' first.\n")
            return False
        return True

    def encrypt_text(self, text: str) -> str:
        nonce = os.urandom(16)
        data = bytearray(text.encode('utf-8'))
        self.aems.encrypt(data, nonce) 
        # Kết quả: Nonce(32 hex chars) + DataHex
        return f"{nonce.hex()}{data.hex()}"

    def decrypt_text(self, encrypted_str: str) -> str:
        # Guard Clause cho độ dài (ít nhất phải có nonce 16 bytes = 32 hex chars)
        if len(encrypted_str) < 32:
            raise ValueError("Data too short to contain a valid Nonce!\n")
            
        n_hex = encrypted_str[:32]
        d_hex = encrypted_str[32:]
        nonce = bytes.fromhex(n_hex)
        data = bytearray(bytes.fromhex(d_hex))
        
        # Gọi hàm decrypt từ thư viện của Tebee
        decrypted_bytes = self.aems.decrypt(data, nonce)
        return decrypted_bytes.decode('utf-8')

    # ... (Các hàm file giữ nguyên logic nhưng bọc thêm màu sắc cho đẹp)
    def encrypt_file_with_magic(self, input_path: str, output_path: str) -> None:
        try:
            with open(input_path, 'r', encoding='utf-8') as f_in, \
                 open(output_path, 'wb') as f_out:
                for line in f_in:
                    if not line: continue
                    nonce = os.urandom(16)
                    f_out.write(nonce)
                    data = bytearray(line.encode('utf-8'))
                    self.aems.encrypt(data, nonce)
                    f_out.write(len(data).to_bytes(2, 'little'))
                    f_out.write(data)
        except Exception as e:
            print(f"{Fore.RED}[File Error]: {e}")

    def decrypt_file_with_magic(self, input_path: str, output_path: str) -> None:
        try:
            with open(input_path, 'rb') as f_in, \
                 open(output_path, 'w', encoding='utf-8') as f_out:
                while True:
                    nonce = f_in.read(16)
                    if len(nonce) < 16: break
                    len_bytes = f_in.read(2)
                    if not len_bytes: break
                    length = int.from_bytes(len_bytes, 'little')
                    encrypted_data = f_in.read(length)
                    decrypted = self.aems.decrypt(bytearray(encrypted_data), nonce)
                    f_out.write(decrypted.decode('utf-8'))
        except Exception as e:
            print(f"{Fore.RED}[File Error]: {e}")

    def print_banner(self) -> None:
        banner = f"""
{Fore.MAGENTA}{Style.BRIGHT}    
     █████╗ ███████╗███╗   ███╗███████╗
    ██╔══██╗██╔════╝████╗ ████║██╔════╝
    ███████║█████╗  ██╔████╔██║███████╗
    ██╔══██║██╔══╝  ██║╚██╔╝██║╚════██║
    ██║  ██║███████╗██║ ╚═╝ ██║███████║
    ╚═╝  ╚═╝╚══════╝╚═╝     ╚═╝╚══════╝
{Fore.CYAN}    --- Advanced Encryption Message System ---
{Fore.GREEN}          [ Made with by Tebee ]
        """
        print(banner + "\n")

    def _run_load_(self, duration, label):
        # Đảm bảo label không có ký tự xuống dòng
        clean_label = label.strip()
        for i in range(101):
            # Tính toán độ dài thanh bar (20 ký tự)
            filled_length = int(i / 5)
            bar = "█" * filled_length + "░" * (20 - filled_length)
            
            # Sử dụng \r để ghi đè lên đúng dòng đó
            # Thêm Fore.CYAN vào đầu mỗi lần lặp để đảm bảo màu sắc không bị mất
            sys.stdout.write(f"\r{Fore.CYAN}{clean_label}: {Fore.GREEN}[{bar}] {i}%")
            sys.stdout.flush()
            time.sleep(duration / 100)
            
        print(f"\n{Fore.GREEN}[SYSTEM READY]")
        self.print_banner()

    def show_help(self) -> None:
        help_text = f"""
{Fore.YELLOW}{'='*40}
{Fore.CYAN}1. create --new          {Fore.WHITE}: Generate fresh key
{Fore.CYAN}2. create --key <hex>    {Fore.WHITE}: Load existing key
{Fore.CYAN}3. encrypt -t <text>     {Fore.WHITE}: Encrypt string
{Fore.CYAN}4. encrypt -f <path>     {Fore.WHITE}: Encrypt file
{Fore.CYAN}5. decrypt -t <hex>      {Fore.WHITE}: Decrypt hex string
{Fore.CYAN}6. decrypt -f <path>     {Fore.WHITE}: Decrypt .aems file
{Fore.CYAN}7. exit                  {Fore.WHITE}: Close application
{Fore.YELLOW}{'='*40}"""
        print(help_text + "\n")

if __name__ == "__main__":
    app = Ter()
    app.run()