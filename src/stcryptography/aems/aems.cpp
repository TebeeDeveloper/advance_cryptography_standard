#include <iostream>
#include <vector>
#include <array>
#include <span>
#include <algorithm>
#include <numeric>
#include <random>
#include <cstdint>
#include <cstring>

/**
 * Hare-chan's Note: 
 * - Em sử dụng std::vector cho buffer để tránh Memory Leak.
 * - S-Box và ShiftRows được xáo trộn dựa trên 128-bit đầu của Master Key.
 * - Cơ chế: Mỗi khối sẽ XOR với khối trước đó (CBC Mode) để tăng tính bảo mật.
 */

class AEMS {
private:
    std::array<uint8_t, 256> sbox;
    std::array<uint8_t, 256> inv_sbox;
    std::array<uint8_t, 16>  shift;
    std::array<uint8_t, 16>  inv_shift;
    std::vector<std::array<uint8_t, 16>> round_keys;
    uint8_t mix_seed;

    void build_dynamic_logic(const uint8_t* key) {
        // Khởi tạo bộ sinh số ngẫu nhiên từ Key
        uint64_t seed1, seed2;
        std::memcpy(&seed1, key, 8);
        std::memcpy(&seed2, key + 8, 8);
        std::mt19937 g(static_cast<uint32_t>(seed1 ^ seed2));

        // 1. Biến đổi S-Box
        std::iota(sbox.begin(), sbox.end(), 0);
        std::shuffle(sbox.begin(), sbox.end(), g);
        for (int i = 0; i < 256; ++i) inv_sbox[sbox[i]] = (uint8_t)i;

        // 2. Biến đổi ShiftRows
        std::iota(shift.begin(), shift.end(), 0);
        std::shuffle(shift.begin(), shift.end(), g);
        for (int i = 0; i < 16; ++i) inv_shift[shift[i]] = (uint8_t)i;

        // 3. Mix Seed
        mix_seed = (uint8_t)(g() % 255 | 1);

        // 4. Key Schedule (8 rounds)
        round_keys.resize(8);
        for (int r = 0; r < 8; ++r) {
            for (int i = 0; i < 16; ++i) {
                round_keys[r][i] = key[i % 32] ^ (uint8_t)(g() & 0xFF);
            }
        }
    }

    // Hàm trộn MixColumns dựa trên khóa
    void mix(std::span<uint8_t, 16> state) {
        for (int i = 0; i < 15; ++i) state[i] ^= (state[i + 1] ^ mix_seed);
    }

    void inv_mix(std::span<uint8_t, 16> state) {
        for (int i = 14; i >= 0; --i) state[i] ^= (state[i + 1] ^ mix_seed);
    }

public:
    explicit AEMS(const uint8_t* master_key) {
        build_dynamic_logic(master_key);
    }

    void encrypt_block(uint8_t* data) {
        std::span<uint8_t, 16> state(data, 16);
        for (int r = 0; r < 8; ++r) {
            for (auto& b : state) b = sbox[b];       // SubBytes
            
            std::array<uint8_t, 16> tmp;             // ShiftRows
            for (int i = 0; i < 16; ++i) tmp[i] = state[shift[i]];
            std::copy(tmp.begin(), tmp.end(), state.begin());

            mix(state);                              // MixColumns
            for (int i = 0; i < 16; ++i) state[i] ^= round_keys[r][i]; // AddRoundKey
        }
    }

    void decrypt_block(uint8_t* data) {
        std::span<uint8_t, 16> state(data, 16);
        for (int r = 7; r >= 0; --r) {
            for (int i = 0; i < 16; ++i) state[i] ^= round_keys[r][i];
            inv_mix(state);

            std::array<uint8_t, 16> tmp;
            for (int i = 0; i < 16; ++i) tmp[i] = state[inv_shift[i]];
            std::copy(tmp.begin(), tmp.end(), state.begin());

            for (auto& b : state) b = inv_sbox[b];
        }
    }
};

// --- Exported C-Style API ---
extern "C" {
    __declspec(dllexport) void GenerateKey256bit(uint8_t* outKey) {
        std::random_device rd;
        std::mt19937_64 gen(rd());
        std::uniform_int_distribution<uint64_t> dis(0, 0xFFFFFFFFFFFFFFFF);

        // Sinh 32 bytes (4 lần 64-bit)
        for (int i = 0; i < 4; ++i) {
            uint64_t rand_val = dis(gen);
            std::memcpy(outKey + (i * 8), &rand_val, 8);
        }
    }

    __declspec(dllexport) void* CreateAEMS(uint8_t* key) {
        return new(std::nothrow) AEMS(key);
    }

    __declspec(dllexport) size_t Encrypt(void* instance, uint8_t* data, size_t len, uint8_t* iv) {
        auto* engine = static_cast<AEMS*>(instance);
        // Padding đơn giản (thêm 0x80 và các số 0)
        size_t padded_len = ((len / 16) + 1) * 16;
        data[len] = 0x80; 
        for(size_t i = len + 1; i < padded_len; ++i) data[i] = 0x00;

        uint8_t prev[16];
        std::memcpy(prev, iv, 16);

        for (size_t i = 0; i < padded_len; i += 16) {
            for (int j = 0; j < 16; ++j) data[i + j] ^= prev[j]; // CBC Mode
            engine->encrypt_block(data + i);
            std::memcpy(prev, data + i, 16);
        }
        return padded_len;
    }

    __declspec(dllexport) size_t Decrypt(void* instance, uint8_t* data, size_t len, uint8_t* iv) {
        auto* engine = static_cast<AEMS*>(instance);
        uint8_t prev[16], next_iv[16];
        std::memcpy(prev, iv, 16);

        for (size_t i = 0; i < len; i += 16) {
            std::memcpy(next_iv, data + i, 16);
            engine->decrypt_block(data + i);
            for (int j = 0; j < 16; ++j) data[i + j] ^= prev[j];
            std::memcpy(prev, next_iv, 16);
        }

        // Unpadding
        for (size_t i = len; i > 0; --i) {
            if (data[i - 1] == 0x80) return i - 1;
        }
        return len;
    }

    __declspec(dllexport) void DeleteAEMS(void* instance) {
        delete static_cast<AEMS*>(instance);
    }
}