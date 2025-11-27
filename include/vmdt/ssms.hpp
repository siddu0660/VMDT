#pragma once

#include <vector>
#include <iostream>
#include <fstream>
#include <cstdint>
#include <stdexcept>
#include <random>
#include <cstring>
#include <cmath>
#include <algorithm>
#include <sstream>
#include <array>

namespace vmdt
{
    namespace crypto
    {
        
        class AES256
        {
        public:
            static constexpr size_t BLOCK_SIZE = 16;
            static constexpr size_t KEY_SIZE = 32;
            static constexpr size_t NONCE_SIZE = 12;
            
            static void encrypt_ctr(std::vector<uint8_t>& data, 
                                   const std::vector<uint8_t>& key,
                                   const std::vector<uint8_t>& nonce)
            {
                if (key.size() != KEY_SIZE) {
                    throw std::invalid_argument("Key must be 32 bytes");
                }
                if (nonce.size() != NONCE_SIZE) {
                    throw std::invalid_argument("Nonce must be 12 bytes");
                }
                
                std::array<uint8_t, BLOCK_SIZE> counter;
                std::copy(nonce.begin(), nonce.end(), counter.begin());
                counter[12] = counter[13] = counter[14] = counter[15] = 0;
                
                size_t block_count = (data.size() + BLOCK_SIZE - 1) / BLOCK_SIZE;
                
                for (size_t block = 0; block < block_count; ++block) {
                    std::array<uint8_t, BLOCK_SIZE> keystream;
                    generate_keystream(counter, key, keystream);
                    
                    size_t start = block * BLOCK_SIZE;
                    size_t end = std::min(start + BLOCK_SIZE, data.size());
                    
                    for (size_t i = start; i < end; ++i) {
                        data[i] ^= keystream[i - start];
                    }
                    
                    increment_counter(counter);
                }
            }
            
            static void decrypt_ctr(std::vector<uint8_t>& data,
                                   const std::vector<uint8_t>& key,
                                   const std::vector<uint8_t>& nonce)
            {
                encrypt_ctr(data, key, nonce);
            }
            
        private:
            static void increment_counter(std::array<uint8_t, BLOCK_SIZE>& counter)
            {
                for (int i = BLOCK_SIZE - 1; i >= 12; --i) {
                    if (++counter[i] != 0) break;
                }
            }
            
            static void generate_keystream(const std::array<uint8_t, BLOCK_SIZE>& counter,
                                          const std::vector<uint8_t>& key,
                                          std::array<uint8_t, BLOCK_SIZE>& output)
            {
                std::array<uint8_t, 4 * 4> state;
                std::copy(counter.begin(), counter.end(), state.begin());
                
                std::array<uint32_t, 60> round_keys;
                key_expansion(key, round_keys);
                
                add_round_key(state, round_keys, 0);
                
                for (int round = 1; round < 14; ++round) {
                    sub_bytes(state);
                    shift_rows(state);
                    mix_columns(state);
                    add_round_key(state, round_keys, round);
                }
                
                sub_bytes(state);
                shift_rows(state);
                add_round_key(state, round_keys, 14);
                
                std::copy(state.begin(), state.end(), output.begin());
            }
            
            static const uint8_t sbox[256];
            static const uint8_t rcon[11];
            
            static uint8_t xtime(uint8_t x) {
                return ((x << 1) ^ (((x >> 7) & 1) * 0x1b));
            }
            
            static uint8_t multiply(uint8_t x, uint8_t y) {
                return (((y & 1) * x) ^
                       ((y >> 1 & 1) * xtime(x)) ^
                       ((y >> 2 & 1) * xtime(xtime(x))) ^
                       ((y >> 3 & 1) * xtime(xtime(xtime(x)))) ^
                       ((y >> 4 & 1) * xtime(xtime(xtime(xtime(x))))));
            }
            
            static void sub_bytes(std::array<uint8_t, 16>& state) {
                for (auto& b : state) b = sbox[b];
            }
            
            static void shift_rows(std::array<uint8_t, 16>& state) {
                uint8_t temp;
                temp = state[1]; state[1] = state[5]; state[5] = state[9]; state[9] = state[13]; state[13] = temp;
                temp = state[2]; state[2] = state[10]; state[10] = temp;
                temp = state[6]; state[6] = state[14]; state[14] = temp;
                temp = state[15]; state[15] = state[11]; state[11] = state[7]; state[7] = state[3]; state[3] = temp;
            }
            
            static void mix_columns(std::array<uint8_t, 16>& state) {
                for (int i = 0; i < 4; ++i) {
                    uint8_t a = state[i*4], b = state[i*4+1], c = state[i*4+2], d = state[i*4+3];
                    state[i*4]   = multiply(a, 2) ^ multiply(b, 3) ^ c ^ d;
                    state[i*4+1] = a ^ multiply(b, 2) ^ multiply(c, 3) ^ d;
                    state[i*4+2] = a ^ b ^ multiply(c, 2) ^ multiply(d, 3);
                    state[i*4+3] = multiply(a, 3) ^ b ^ c ^ multiply(d, 2);
                }
            }
            
            static void add_round_key(std::array<uint8_t, 16>& state, 
                                     const std::array<uint32_t, 60>& round_keys, int round) {
                for (int i = 0; i < 4; ++i) {
                    uint32_t rk = round_keys[round * 4 + i];
                    state[i*4]   ^= (rk >> 24) & 0xFF;
                    state[i*4+1] ^= (rk >> 16) & 0xFF;
                    state[i*4+2] ^= (rk >> 8) & 0xFF;
                    state[i*4+3] ^= rk & 0xFF;
                }
            }
            
            static void key_expansion(const std::vector<uint8_t>& key, 
                                     std::array<uint32_t, 60>& round_keys) {
                for (int i = 0; i < 8; ++i) {
                    round_keys[i] = ((uint32_t)key[4*i] << 24) | ((uint32_t)key[4*i+1] << 16) |
                                   ((uint32_t)key[4*i+2] << 8) | key[4*i+3];
                }
                
                for (int i = 8; i < 60; ++i) {
                    uint32_t temp = round_keys[i-1];
                    if (i % 8 == 0) {
                        temp = ((uint32_t)sbox[(temp >> 16) & 0xFF] << 24) |
                               ((uint32_t)sbox[(temp >> 8) & 0xFF] << 16) |
                               ((uint32_t)sbox[temp & 0xFF] << 8) |
                               sbox[(temp >> 24) & 0xFF];
                        temp ^= ((uint32_t)rcon[i/8] << 24);
                    } else if (i % 8 == 4) {
                        temp = ((uint32_t)sbox[(temp >> 24) & 0xFF] << 24) |
                               ((uint32_t)sbox[(temp >> 16) & 0xFF] << 16) |
                               ((uint32_t)sbox[(temp >> 8) & 0xFF] << 8) |
                               sbox[temp & 0xFF];
                    }
                    round_keys[i] = round_keys[i-8] ^ temp;
                }
            }
        };
        
        inline const uint8_t AES256::sbox[256] = {
            0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
            0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
            0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
            0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,
            0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,
            0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
            0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,
            0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,
            0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
            0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,
            0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
            0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
            0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,
            0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,
            0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
            0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16
        };
        
        inline const uint8_t AES256::rcon[11] = {
            0x00, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36
        };

        
        class GF256
        {
        public:
            static uint8_t add(uint8_t a, uint8_t b) { return a ^ b; }
            static uint8_t sub(uint8_t a, uint8_t b) { return a ^ b; }
            
            static uint8_t mul(uint8_t a, uint8_t b)
            {
                if (a == 0 || b == 0) return 0;
                return exp_table[(log_table[a] + log_table[b]) % 255];
            }
            
            static uint8_t div(uint8_t a, uint8_t b)
            {
                if (b == 0) throw std::invalid_argument("Division by zero in GF(256)");
                if (a == 0) return 0;
                int diff = log_table[a] - log_table[b];
                if (diff < 0) diff += 255;
                return exp_table[diff];
            }
            
            static uint8_t inv(uint8_t a)
            {
                if (a == 0) throw std::invalid_argument("Inverse of zero in GF(256)");
                return exp_table[255 - log_table[a]];
            }
            
            static uint8_t pow(uint8_t base, uint8_t exp)
            {
                if (base == 0) return (exp == 0) ? 1 : 0;
                int result = (log_table[base] * exp) % 255;
                return exp_table[result];
            }
            
            static uint8_t eval_poly(const std::vector<uint8_t> &coeffs, uint8_t x)
            {
                if (coeffs.empty()) return 0;
                uint8_t result = coeffs.back();
                for (int i = static_cast<int>(coeffs.size()) - 2; i >= 0; --i)
                {
                    result = add(mul(result, x), coeffs[i]);
                }
                return result;
            }
            
        private:
            static const uint8_t exp_table[256];
            static const uint8_t log_table[256];
        };

        inline const uint8_t GF256::exp_table[256] = {
            1, 3, 5, 15, 17, 51, 85, 255, 26, 46, 114, 150, 161, 248, 19, 53,
            95, 225, 56, 72, 216, 115, 149, 164, 247, 2, 6, 10, 30, 34, 102, 170,
            229, 52, 92, 228, 55, 89, 235, 38, 106, 190, 217, 112, 144, 171, 230, 49,
            83, 245, 4, 12, 20, 60, 68, 204, 79, 209, 104, 184, 211, 110, 178, 205,
            76, 212, 103, 169, 224, 59, 77, 215, 98, 166, 241, 8, 24, 40, 120, 136,
            131, 158, 185, 208, 107, 189, 220, 127, 129, 152, 179, 206, 73, 219, 118, 154,
            181, 196, 87, 249, 16, 48, 80, 240, 11, 29, 39, 105, 187, 214, 97, 163,
            254, 25, 43, 125, 135, 146, 173, 236, 47, 113, 147, 174, 233, 32, 96, 160,
            251, 22, 58, 78, 210, 109, 183, 194, 93, 231, 50, 86, 250, 21, 63, 65,
            195, 94, 226, 61, 71, 201, 64, 192, 91, 237, 44, 116, 156, 191, 218, 117,
            159, 186, 213, 100, 172, 239, 42, 126, 130, 157, 188, 223, 122, 142, 137, 128,
            155, 182, 193, 88, 232, 35, 101, 175, 234, 37, 111, 177, 200, 67, 197, 84,
            252, 31, 33, 99, 165, 244, 7, 9, 27, 45, 119, 153, 176, 203, 70, 202,
            69, 207, 74, 222, 121, 139, 134, 145, 168, 227, 62, 66, 198, 81, 243, 14,
            18, 54, 90, 238, 41, 123, 141, 140, 143, 138, 133, 148, 167, 242, 13, 23,
            57, 75, 221, 124, 132, 151, 162, 253, 28, 36, 108, 180, 199, 82, 246, 1
        };
        
        inline const uint8_t GF256::log_table[256] = {
            0, 0, 25, 1, 50, 2, 26, 198, 75, 199, 27, 104, 51, 238, 223, 3,
            100, 4, 224, 14, 52, 141, 129, 239, 76, 113, 8, 200, 248, 105, 28, 193,
            125, 194, 29, 181, 249, 185, 39, 106, 77, 228, 166, 114, 154, 201, 9, 120,
            101, 47, 138, 5, 33, 15, 225, 36, 18, 240, 130, 69, 53, 147, 218, 142,
            150, 143, 219, 189, 54, 208, 206, 148, 19, 92, 210, 241, 64, 70, 131, 56,
            102, 221, 253, 48, 191, 6, 139, 98, 179, 37, 226, 152, 34, 136, 145, 16,
            126, 110, 72, 195, 163, 182, 30, 66, 58, 107, 40, 84, 250, 133, 61, 186,
            43, 121, 10, 21, 155, 159, 94, 202, 78, 212, 172, 229, 243, 115, 167, 87,
            175, 88, 168, 80, 244, 234, 214, 116, 79, 174, 233, 213, 231, 230, 173, 232,
            44, 215, 117, 122, 235, 22, 11, 245, 89, 203, 95, 176, 156, 169, 81, 160,
            127, 12, 246, 111, 23, 196, 73, 236, 216, 67, 31, 45, 164, 118, 123, 183,
            204, 187, 62, 90, 251, 96, 177, 134, 59, 82, 161, 108, 170, 85, 41, 157,
            151, 178, 135, 144, 97, 190, 220, 252, 188, 149, 207, 205, 55, 63, 91, 209,
            83, 57, 132, 60, 65, 162, 109, 71, 20, 42, 158, 93, 86, 242, 211, 171,
            68, 17, 146, 217, 35, 32, 46, 137, 180, 124, 184, 38, 119, 153, 227, 165,
            103, 74, 237, 222, 197, 49, 254, 24, 13, 99, 140, 128, 192, 247, 112, 7
        };

        class SimpleSSS
        {
        public:
            struct Share
            {
                uint8_t x;
                std::vector<uint8_t> y;
                size_t k_threshold;
            };

            static std::vector<Share> split_key_secret(
                const std::vector<uint8_t> &secret,
                int k,
                int n)
            {
                std::vector<Share> shares(n);
                std::random_device rd;
                std::mt19937 gen(rd());
                std::uniform_int_distribution<> distrib(1, 255);

                for (int i = 0; i < n; ++i)
                {
                    shares[i].x = static_cast<uint8_t>(i + 1);
                    shares[i].k_threshold = k;
                    shares[i].y.resize(secret.size());
                }

                for (size_t byte_idx = 0; byte_idx < secret.size(); ++byte_idx)
                {
                    std::vector<uint8_t> coeffs(k);
                    coeffs[0] = secret[byte_idx];
                    for (int i = 1; i < k; ++i)
                    {
                        coeffs[i] = static_cast<uint8_t>(distrib(gen));
                    }
                    
                    for (int i = 0; i < n; ++i)
                    {
                        shares[i].y[byte_idx] = GF256::eval_poly(coeffs, shares[i].x);
                    }
                }
                return shares;
            }

            static std::vector<uint8_t> reconstruct_key_secret(const std::vector<Share> &shares)
            {
                if (shares.empty())
                    return {};
                    
                size_t k = shares[0].k_threshold;
                if (shares.size() < k)
                    throw std::invalid_argument("Need at least k shares for reconstruction");
                    
                size_t key_size = shares[0].y.size();
                std::vector<uint8_t> reconstructed(key_size, 0);

                for (size_t byte_idx = 0; byte_idx < key_size; ++byte_idx)
                {
                    uint8_t secret_byte = 0;
                    
                    for (size_t i = 0; i < k; ++i)
                    {
                        uint8_t xi = shares[i].x;
                        uint8_t yi = shares[i].y[byte_idx];
                        
                        uint8_t numerator = 1;
                        uint8_t denominator = 1;
                        
                        for (size_t j = 0; j < k; ++j)
                        {
                            if (i != j)
                            {
                                uint8_t xj = shares[j].x;
                                numerator = GF256::mul(numerator, xj);
                                denominator = GF256::mul(denominator, GF256::sub(xj, xi));
                            }
                        }
                        
                        uint8_t lagrange = GF256::mul(yi, GF256::div(numerator, denominator));
                        secret_byte = GF256::add(secret_byte, lagrange);
                    }
                    
                    reconstructed[byte_idx] = secret_byte;
                }

                return reconstructed;
            }
        };

        
        
        static constexpr size_t SSMS_BLOCK_SIZE = 16;
        static constexpr size_t SSMS_KEY_SIZE = 32;  
        static constexpr size_t SSMS_NONCE_SIZE = 12;

        static std::vector<uint8_t> generate_random_bytes(size_t size)
        {
            std::vector<uint8_t> bytes(size);
            std::random_device rd;
            std::mt19937 gen(rd());
            std::uniform_int_distribution<> distrib(0, 255);
            for (size_t i = 0; i < size; ++i)
            {
                bytes[i] = static_cast<uint8_t>(distrib(gen));
            }
            return bytes;
        }

        
        
        

        class SSMS
        {
        public:
            struct Share
            {
                std::vector<uint8_t> key_share;
                std::vector<uint8_t> data_share;
                std::vector<uint8_t> nonce;
                size_t original_size;
                size_t k_threshold;
                uint8_t share_index;
            };

            
            static std::vector<Share> split(
                const std::vector<uint8_t> &secret,
                int k, 
                int n  
            )
            {
                if (k > n || k < 2 || n > 255 || n < 1)
                {
                    throw std::invalid_argument("Invalid k or n parameters");
                }
                if (secret.empty())
                {
                    throw std::invalid_argument("Secret cannot be empty");
                }

                std::vector<uint8_t> master_key = generate_random_bytes(SSMS_KEY_SIZE);
                std::vector<uint8_t> nonce = generate_random_bytes(SSMS_NONCE_SIZE);
                
                std::vector<uint8_t> encrypted_data = secret;
                AES256::encrypt_ctr(encrypted_data, master_key, nonce);

                auto key_shares = SimpleSSS::split_key_secret(master_key, k, n);

                std::vector<Share> final_shares(n);
                for (int i = 0; i < n; ++i)
                {
                    final_shares[i].data_share = encrypted_data;
                    final_shares[i].key_share = key_shares[i].y;
                    final_shares[i].nonce = nonce;
                    final_shares[i].original_size = secret.size();
                    final_shares[i].k_threshold = k;
                    final_shares[i].share_index = static_cast<uint8_t>(i + 1);
                }

                return final_shares;
            }

            static std::vector<uint8_t> reconstruct(
                const std::vector<Share> &shares)
            {
                if (shares.empty())
                {
                    throw std::invalid_argument("No shares provided");
                }
                
                size_t k = shares[0].k_threshold;
                if (shares.size() < k)
                {
                    throw std::invalid_argument("Need at least k=" + std::to_string(k) + " shares");
                }

                std::vector<SimpleSSS::Share> key_shares;
                for (size_t i = 0; i < k; ++i)
                { 
                    SimpleSSS::Share s;
                    s.x = shares[i].share_index;
                    s.y = shares[i].key_share;
                    s.k_threshold = k;
                    key_shares.push_back(s);
                }
                std::vector<uint8_t> master_key = SimpleSSS::reconstruct_key_secret(key_shares);

                std::vector<uint8_t> decrypted_data = shares[0].data_share;
                AES256::decrypt_ctr(decrypted_data, master_key, shares[0].nonce);

                decrypted_data.resize(shares[0].original_size);
                return decrypted_data;
            }

            
            static std::vector<std::vector<uint8_t>> split_simple(
                const std::vector<uint8_t> &secret,
                int k,
                int n)
            {
                auto shares = split(secret, k, n);
                std::vector<std::vector<uint8_t>> result(n);

                for (size_t i = 0; i < shares.size(); i++)
                {
                    result[i].push_back(static_cast<uint8_t>(i + 1)); 

                    uint32_t orig_size = static_cast<uint32_t>(shares[i].original_size);
                    result[i].push_back((orig_size >> 24) & 0xFF);
                    result[i].push_back((orig_size >> 16) & 0xFF);
                    result[i].push_back((orig_size >> 8) & 0xFF);
                    result[i].push_back(orig_size & 0xFF);

                    result[i].push_back(static_cast<uint8_t>(shares[i].k_threshold));

                    uint32_t key_size = static_cast<uint32_t>(shares[i].key_share.size());
                    result[i].push_back((key_size >> 24) & 0xFF);
                    result[i].push_back((key_size >> 16) & 0xFF);
                    result[i].push_back((key_size >> 8) & 0xFF);
                    result[i].push_back(key_size & 0xFF);

                    result[i].insert(result[i].end(), shares[i].nonce.begin(), shares[i].nonce.end());
                    
                    result[i].insert(result[i].end(), shares[i].key_share.begin(), shares[i].key_share.end());
                    
                    result[i].insert(result[i].end(), shares[i].data_share.begin(), shares[i].data_share.end());
                }

                return result;
            }

            static std::vector<uint8_t> reconstruct_simple(
                const std::vector<std::vector<uint8_t>> &raw_shares)
            {
                std::vector<Share> shares;

                for (const auto &raw : raw_shares)
                {
                    if (raw.size() < 10 + SSMS_NONCE_SIZE + SSMS_KEY_SIZE)
                        continue;

                    Share s;
                    s.share_index = raw[0];
                    
                    s.original_size = (static_cast<uint32_t>(raw[1]) << 24) |
                                      (static_cast<uint32_t>(raw[2]) << 16) |
                                      (static_cast<uint32_t>(raw[3]) << 8) |
                                      (static_cast<uint32_t>(raw[4]));

                    s.k_threshold = raw[5];

                    uint32_t key_size = (static_cast<uint32_t>(raw[6]) << 24) |
                                        (static_cast<uint32_t>(raw[7]) << 16) |
                                        (static_cast<uint32_t>(raw[8]) << 8) |
                                        (static_cast<uint32_t>(raw[9]));

                    size_t nonce_start = 10;
                    size_t key_start = nonce_start + SSMS_NONCE_SIZE;
                    size_t data_start = key_start + key_size;
                    
                    s.nonce.assign(raw.begin() + nonce_start, raw.begin() + key_start);
                    s.key_share.assign(raw.begin() + key_start, raw.begin() + data_start);
                    s.data_share.assign(raw.begin() + data_start, raw.end());
                    shares.push_back(s);
                }

                if (shares.empty()) {
                    throw std::invalid_argument("No valid shares provided");
                }
                
                size_t k = shares[0].k_threshold;
                if (shares.size() < k) {
                    throw std::invalid_argument("Need at least " + std::to_string(k) + 
                                               " shares for reconstruction, got " + std::to_string(shares.size()));
                }

                return reconstruct(shares);
            }

            
            static std::vector<uint8_t> read_file(const std::string &filepath)
            {
                std::ifstream file(filepath, std::ios::binary);
                if (!file)
                {
                    throw std::runtime_error("Cannot open file: " + filepath);
                }

                file.seekg(0, std::ios::end);
                size_t size = file.tellg();
                file.seekg(0, std::ios::beg);

                std::vector<uint8_t> buffer(size);
                file.read(reinterpret_cast<char *>(buffer.data()), size);

                if (!file)
                {
                    throw std::runtime_error("Error reading file: " + filepath);
                }

                return buffer;
            }

            static void write_file(const std::string &filepath, const std::vector<uint8_t> &data)
            {
                std::ofstream file(filepath, std::ios::binary);
                if (!file)
                {
                    throw std::runtime_error("Cannot create file: " + filepath);
                }

                file.write(reinterpret_cast<const char *>(data.data()), data.size());

                if (!file)
                {
                    throw std::runtime_error("Error writing file: " + filepath);
                }
            }

            static void save_shares(const std::vector<std::vector<uint8_t>> &shares,
                                    const std::string &base_filename)
            {
                size_t total_size = 0;
                for (size_t i = 0; i < shares.size(); i++)
                {
                    std::string filename = base_filename + "_share" + std::to_string(i + 1) + ".bin";
                    write_file(filename, shares[i]);
                    total_size += shares[i].size();
                    std::cout << "  Saved: " << filename << " (" << shares[i].size() << " bytes)\n";
                }
                std::cout << "  Total storage: " << total_size << " bytes\n";
            }

            static std::vector<std::vector<uint8_t>> load_shares(const std::vector<std::string> &filenames)
            {
                std::vector<std::vector<uint8_t>> shares;

                for (const auto &filename : filenames)
                {
                    try
                    {
                        auto share = read_file(filename);
                        shares.push_back(share);
                        std::cout << "  Loaded: " << filename << " (" << share.size() << " bytes)\n";
                    }
                    catch (const std::exception &e)
                    {
                        std::cerr << "  Warning: " << e.what() << "\n";
                    }
                }

                return shares;
            }
        };

        
        
        

    } 
} 