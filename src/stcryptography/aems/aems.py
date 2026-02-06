import ctypes
import os

class AEMSCipher:
    # Hare's Note: Anh nhớ build file C++ ra "aems.dll" cùng thư mục nhé!
    _lib = ctypes.CDLL(os.path.abspath("aems.dll"))

    def __init__(self, key: bytes):
        if len(key) != 32:
            raise ValueError("Tebee-kun! Khóa phải đủ 32 bytes nhé! 💢")
        
        self._lib.CreateAEMS.restype = ctypes.c_void_p
        self._lib.CreateAEMS.argtypes = [ctypes.c_char_p]
        self.handle = self._lib.CreateAEMS(key)

    @staticmethod
    def generate_key() -> bytes:
        """
        Gọi trực tiếp logic sinh khóa ngẫu nhiên từ C++20.
        Siêu an toàn và siêu ngẫu nhiên luôn! ✨
        """
        key_buffer = ctypes.create_string_buffer(32)
        # Thiết lập kiểu đối số cho hàm C++
        AEMSCipher._lib.GenerateKey256bit.argtypes = [ctypes.c_char_p]
        AEMSCipher._lib.GenerateKey256bit(key_buffer)
        return key_buffer.raw

    def encrypt(self, data: bytes, iv: bytes) -> bytes:
        if len(iv) != 16: raise ValueError("IV phải là 16 bytes!")
        
        # Tạo đệm dữ liệu (Padding space)
        padded_size = ((len(data) // 16) + 1) * 16
        # Tạo buffer đủ lớn để chứa dữ liệu đã pad
        buffer = ctypes.create_string_buffer(padded_size)
        buffer.value = data
        
        iv_ptr = ctypes.create_string_buffer(iv, 16)
        
        self._lib.Encrypt.restype = ctypes.c_size_t
        self._lib.Encrypt.argtypes = [ctypes.c_void_p, ctypes.c_char_p, ctypes.c_size_t, ctypes.c_char_p]
        
        final_len = self._lib.Encrypt(self.handle, buffer, len(data), iv_ptr)
        return buffer.raw[:final_len]

    def decrypt(self, encrypted_data: bytes, iv: bytes) -> bytes:
        buffer = ctypes.create_string_buffer(encrypted_data)
        iv_ptr = ctypes.create_string_buffer(iv, 16)
        
        self._lib.Decrypt.restype = ctypes.c_size_t
        self._lib.Decrypt.argtypes = [ctypes.c_void_p, ctypes.c_char_p, ctypes.c_size_t, ctypes.c_char_p]
        
        original_len = self._lib.Decrypt(self.handle, buffer, len(encrypted_data), iv_ptr)
        return buffer.raw[:original_len]

    def __del__(self):
        if hasattr(self, 'handle'):
            self._lib.DeleteAEMS.argtypes = [ctypes.c_void_p]
            self._lib.DeleteAEMS(self.handle)

# --- Test Drive cho Tebee-kun ---
if __name__ == "__main__":
    # Bước 1: Sinh khóa từ C++ thông qua staticmethod
    secret_key = AEMSCipher.generate_random_key()
    initial_vector = os.urandom(16) # IV có thể dùng urandom cho nhanh
    
    # Bước 2: Khởi tạo engine
    cipher = AEMSCipher(secret_key)
    
    # Bước 3: Mã hóa lời nhắn bí mật
    msg = b"Hare-chan loves Tebee-kun's clean code!"
    encrypted = cipher.encrypt(msg, initial_vector)
    
    # Bước 4: Giải mã
    decrypted = cipher.decrypt(encrypted, initial_vector)
    
    print(f"Key (hex): {secret_key.hex()}")
    print(f"Encrypted: {encrypted.hex()}")
    print(f"Decrypted: {decrypted.decode()}")