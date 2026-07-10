// AES256.h
#ifndef AES256_H
#define AES256_H

// 基础Arduino系统头文件
#include <Arduino.h>
// mbedtls 加密算法依赖
#include <mbedtls/gcm.h>
#include <mbedtls/ctr_drbg.h>
#include <mbedtls/entropy.h>
#include <mbedtls/sha256.h>
#include <mbedtls/base64.h>
#include <mbedtls/aes.h>
#include <string.h>
#include <stdlib.h>

// ===================== 安全工具宏定义 =====================
/**
 * @brief 安全释放堆内存并置空指针，防止野指针重复释放
 * @param buf 待释放的uint8_t堆缓冲区指针
 */
#define SAFE_FREE(buf) do { if((buf) != nullptr) { memset((buf), 0, strlen((char*)buf)); free(buf); (buf) = nullptr; } } while(0)

/**
 * @brief 安全擦除栈内存敏感数据（密钥/IV/Tag）
 * @param data 栈数组变量
 */
#define SEC_CLEAR_STACK(data) memset((data), 0, sizeof(data))

/**
 * @brief 最大明文长度限制，防止超大文本耗尽堆内存
 */
#define AES_MAX_PLAIN_LEN 1024

/**
 * @brief AES256加解密工具类
 * 支持两种加密模式：GCM(带完整性校验，推荐) / CTR(流式无校验)
 * 数据存储格式：Base64(IV + 密文 + [GCM认证Tag])
 * 密钥派生：SHA256哈希密码直接生成32字节密钥，兼容ESP32默认mbedtls，无PBKDF2依赖
 * 适用平台：ESP32 Arduino（内置mbedtls 2.0.12及更低版本）
 */
class AES256 {
public:
    /**
     * @brief 加密模式枚举
     * MODE_GCM：AES-GCM 12字节IV，带16字节Tag完整性校验，防篡改，优先使用
     * MODE_CTR：AES-CTR 16字节IV，无校验，仅加密，存在篡改风险
     */
    enum Mode {
        MODE_GCM,
        MODE_CTR
    };

    /**
     * @brief 文本AES256加密入口
     * @param plaintext 输入明文字符串，限制最大长度AES_MAX_PLAIN_LEN
     * @param password  用户原始密码字符串（任意长度，内部SHA256派生32字节AES密钥）
     * @param mode      加密模式 MODE_GCM / MODE_CTR
     * @param output    输出Base64编码密文，失败时会清空该字符串
     * @return true=加密全部流程无错误；false=入参/内存/随机数/加密算法出错
     * @note 密文二进制结构：[IV(12/16字节)] + [密文N字节] + [Tag(16字节，仅GCM)]
     */
    static bool encrypt(const String& plaintext, const String& password, Mode mode, String& output) {
        // 每次加密前置清空输出，避免残留旧数据干扰判断
        output.clear();

        // ========== 入参合法性校验 ==========
        // 明文/密码不能为空
        if (plaintext.isEmpty() || password.isEmpty()) {
            return false;
        }
        // 限制明文最大长度，防止堆内存溢出、DoS攻击
        if (plaintext.length() > AES_MAX_PLAIN_LEN) {
            return false;
        }

        // ========== 变量预定义（栈分配，避免频繁malloc） ==========
        uint8_t aes_key[32] = {0};          // AES256密钥 固定32字节
        int iv_byte_len = (mode == MODE_GCM) ? 12 : 16;
        uint8_t iv_buf[16] = {0};           // IV缓冲区，最大16字节兼容两种模式
        size_t plain_len = plaintext.length();
        bool encrypt_success = false;

        // ========== 步骤1：SHA256从用户密码派生32字节AES256密钥 ==========
        if (!deriveKey(password, aes_key, 32)) {
            SEC_CLEAR_STACK(aes_key);
            return false;
        }

        // ========== 步骤2：初始化mbedtls随机熵源与DRBG伪随机发生器 ==========
        mbedtls_entropy_context entropy;
        mbedtls_ctr_drbg_context ctr_drbg;
        mbedtls_entropy_init(&entropy);
        mbedtls_ctr_drbg_init(&ctr_drbg);

        // 个性化字符串，增加随机熵多样性，区分本程序随机流
        const char pers_str[] = "AES256_AES256_ESP32_RNG";
        int rng_seed_ret = mbedtls_ctr_drbg_seed(
            &ctr_drbg,
            mbedtls_entropy_func,
            &entropy,
            (const unsigned char*)pers_str,
            sizeof(pers_str) - 1
        );
        // 随机数种子初始化失败，释放上下文直接退出
        if (rng_seed_ret != 0) {
            mbedtls_ctr_drbg_free(&ctr_drbg);
            mbedtls_entropy_free(&entropy);
            SEC_CLEAR_STACK(aes_key);
            return false;
        }

        // ========== 步骤3：生成密码学安全随机IV ==========
        int iv_rand_ret = mbedtls_ctr_drbg_random(&ctr_drbg, iv_buf, iv_byte_len);
        if (iv_rand_ret != 0) {
            // IV生成失败，释放资源
            mbedtls_ctr_drbg_free(&ctr_drbg);
            mbedtls_entropy_free(&entropy);
            SEC_CLEAR_STACK(aes_key);
            SEC_CLEAR_STACK(iv_buf);
            return false;
        }

        // ========== 步骤4：分配密文堆缓冲区 ==========
        // 预留额外32字节冗余，兼容GCM Tag、对齐填充
        size_t cipher_max_size = plain_len + 32;
        uint8_t* cipher_buf = (uint8_t*)malloc(cipher_max_size);
        if (cipher_buf == nullptr) {
            // 堆内存分配失败，释放所有上下文
            mbedtls_ctr_drbg_free(&ctr_drbg);
            mbedtls_entropy_free(&entropy);
            SEC_CLEAR_STACK(aes_key);
            SEC_CLEAR_STACK(iv_buf);
            return false;
        }
        memset(cipher_buf, 0, cipher_max_size);
        size_t cipher_actual_len = 0;
        uint8_t gcm_tag[16] = {0}; // GCM认证标签，仅GCM模式使用

        // ========== 步骤5：分模式执行AES加密运算 ==========
        if (mode == MODE_GCM) {
            // ---------------- AES-GCM 加密流程 ----------------
            mbedtls_gcm_context gcm_ctx;
            mbedtls_gcm_init(&gcm_ctx);

            // 加载256位AES密钥至GCM上下文
            int setkey_ret = mbedtls_gcm_setkey(&gcm_ctx, MBEDTLS_CIPHER_ID_AES, aes_key, 256);
            if (setkey_ret == 0) {
                // GCM加密：无附加AD认证数据，输出16字节Tag
                int crypt_ret = mbedtls_gcm_crypt_and_tag(
                    &gcm_ctx,
                    MBEDTLS_GCM_ENCRYPT,
                    plain_len,
                    iv_buf, iv_byte_len,
                    nullptr, 0,               // AD附加数据：无
                    (const uint8_t*)plaintext.c_str(),
                    cipher_buf,
                    16, gcm_tag
                );
                if (crypt_ret == 0) {
                    cipher_actual_len = plain_len;
                    encrypt_success = true;
                }
            }
            // 释放GCM上下文，擦除内部密钥缓存
            mbedtls_gcm_free(&gcm_ctx);
        } else {
            // ---------------- AES-CTR 加密流程 ----------------
            mbedtls_aes_context aes_ctx;
            mbedtls_aes_init(&aes_ctx);

            int setkey_ret = mbedtls_aes_setkey_enc(&aes_ctx, aes_key, 256);
            if (setkey_ret == 0) {
                uint8_t stream_block[16] = {0};
                size_t nc_offset = 0; // CTR流加密块偏移，每次必须清零
                int crypt_ret = mbedtls_aes_crypt_ctr(
                    &aes_ctx,
                    plain_len,
                    &nc_offset,
                    iv_buf, stream_block,
                    (const uint8_t*)plaintext.c_str(),
                    cipher_buf
                );
                if (crypt_ret == 0) {
                    cipher_actual_len = plain_len;
                    encrypt_success = true;
                }
            }
            // 释放AES上下文
            mbedtls_aes_free(&aes_ctx);
        }

        // ========== 加密运算失败处理：释放资源直接返回 ==========
        if (!encrypt_success) {
            SAFE_FREE(cipher_buf);
            mbedtls_ctr_drbg_free(&ctr_drbg);
            mbedtls_entropy_free(&entropy);
            SEC_CLEAR_STACK(aes_key);
            SEC_CLEAR_STACK(iv_buf);
            SEC_CLEAR_STACK(gcm_tag);
            return false;
        }

        // ========== 步骤6：拼接二进制数据包 IV + 密文 + [GCM Tag] ==========
        size_t total_bin_len = iv_byte_len + cipher_actual_len;
        // GCM模式追加16字节校验Tag
        if (mode == MODE_GCM) {
            total_bin_len += 16;
        }
        uint8_t* bin_pack = (uint8_t*)malloc(total_bin_len);
        if (bin_pack == nullptr) {
            SAFE_FREE(cipher_buf);
            mbedtls_ctr_drbg_free(&ctr_drbg);
            mbedtls_entropy_free(&entropy);
            SEC_CLEAR_STACK(aes_key);
            SEC_CLEAR_STACK(iv_buf);
            SEC_CLEAR_STACK(gcm_tag);
            return false;
        }
        memset(bin_pack, 0, total_bin_len);

        // 分段拷贝二进制数据
        memcpy(bin_pack, iv_buf, iv_byte_len);
        memcpy(bin_pack + iv_byte_len, cipher_buf, cipher_actual_len);
        if (mode == MODE_GCM) {
            memcpy(bin_pack + iv_byte_len + cipher_actual_len, gcm_tag, 16);
        }

        // ========== 步骤7：二进制包Base64编码输出 ==========
        size_t b64_output_size = 0;
        // 第一次调用：仅计算Base64所需缓冲区长度
        int b64_len_ret = mbedtls_base64_encode(nullptr, 0, &b64_output_size, bin_pack, total_bin_len);
        if (b64_len_ret == MBEDTLS_ERR_BASE64_BUFFER_TOO_SMALL) {
            // 分配Base64字符串缓冲区，+1存放字符串结束符
            char* b64_str_buf = (char*)malloc(b64_output_size + 1);
            if (b64_str_buf != nullptr) {
                memset(b64_str_buf, 0, b64_output_size + 1);
                // 第二次调用：实际编码
                int b64_encode_ret = mbedtls_base64_encode(
                    (uint8_t*)b64_str_buf,
                    b64_output_size,
                    &b64_output_size,
                    bin_pack,
                    total_bin_len
                );
                // 编码成功赋值输出字符串
                if (b64_encode_ret == 0) {
                    b64_str_buf[b64_output_size] = '\0';
                    output = String(b64_str_buf);
                }
                SAFE_FREE(b64_str_buf);
            }
        }

        // ========== 资源统一释放清理（敏感数据全部清零擦除） ==========
        SAFE_FREE(bin_pack);
        SAFE_FREE(cipher_buf);
        mbedtls_ctr_drbg_free(&ctr_drbg);
        mbedtls_entropy_free(&entropy);
        SEC_CLEAR_STACK(aes_key);
        SEC_CLEAR_STACK(iv_buf);
        SEC_CLEAR_STACK(gcm_tag);

        // 输出字符串非空即代表全部流程成功
        return !output.isEmpty();
    }

    /**
     * @brief Base64密文解密入口
     * @param ciphertext_base64 加密生成的Base64密文字符串
     * @param password 加密时使用的相同用户密码
     * @param mode 加密时使用的模式，必须完全一致否则解密失败
     * @param output 解密输出明文字符串，失败自动清空
     * @return true=解密校验通过；false=解码失败/长度不足/Tag校验错误/内存错误
     * @note GCM模式会校验Tag，密文篡改、密码错误直接返回false，安全性更高
     */
    static bool decrypt(const String& ciphertext_base64, const String& password, Mode mode, String& output) {
        output.clear();
        int iv_byte_len = (mode == MODE_GCM) ? 12 : 16;

        // ========== 入参校验 ==========
        if (ciphertext_base64.isEmpty() || password.isEmpty()) {
            return false;
        }

        // ========== 步骤1：Base64解码二进制原始数据包 ==========
        size_t decode_bin_len = 0;
        // 预计算解码后二进制长度
        int b64_calc_ret = mbedtls_base64_decode(
            nullptr, 0, &decode_bin_len,
            (const uint8_t*)ciphertext_base64.c_str(),
            ciphertext_base64.length()
        );
        if (b64_calc_ret != MBEDTLS_ERR_BASE64_BUFFER_TOO_SMALL) {
            // 非法Base64字符串，编码格式损坏
            return false;
        }

        uint8_t* decode_bin_buf = (uint8_t*)malloc(decode_bin_len + 1);
        if (decode_bin_buf == nullptr) return false;
        memset(decode_bin_buf, 0, decode_bin_len + 1);

        // 执行Base64解码
        int b64_decode_ret = mbedtls_base64_decode(
            decode_bin_buf, decode_bin_len, &decode_bin_len,
            (const uint8_t*)ciphertext_base64.c_str(),
            ciphertext_base64.length()
        );
        if (b64_decode_ret != 0) {
            SAFE_FREE(decode_bin_buf);
            return false;
        }

        // ========== 步骤2：校验二进制包最小长度，防止内存越界读取 ==========
        // 基础长度：至少包含完整IV
        if (decode_bin_len < iv_byte_len) {
            SAFE_FREE(decode_bin_buf);
            return false;
        }
        // GCM额外要求：IV + 至少1字节密文 + 16字节Tag
        if (mode == MODE_GCM && decode_bin_len < (iv_byte_len + 16 + 1)) {
            SAFE_FREE(decode_bin_buf);
            return false;
        }

        // ========== 拆分IV、密文、Tag ==========
        uint8_t iv_buf[16] = {0};
        memcpy(iv_buf, decode_bin_buf, iv_byte_len);

        size_t cipher_data_len = 0;
        uint8_t* cipher_data_buf = nullptr;
        uint8_t gcm_tag[16] = {0};

        if (mode == MODE_GCM) {
            // GCM：最后16字节为Tag，中间部分是密文
            cipher_data_len = decode_bin_len - iv_byte_len - 16;
            cipher_data_buf = (uint8_t*)malloc(cipher_data_len + 32);
            if (cipher_data_buf == nullptr) {
                SAFE_FREE(decode_bin_buf);
                SEC_CLEAR_STACK(iv_buf);
                return false;
            }
            memset(cipher_data_buf, 0, cipher_data_len + 32);
            memcpy(cipher_data_buf, decode_bin_buf + iv_byte_len, cipher_data_len);
            memcpy(gcm_tag, decode_bin_buf + iv_byte_len + cipher_data_len, 16);
        } else {
            // CTR：无Tag，剩余全部为密文
            cipher_data_len = decode_bin_len - iv_byte_len;
            cipher_data_buf = (uint8_t*)malloc(cipher_data_len + 32);
            if (cipher_data_buf == nullptr) {
                SAFE_FREE(decode_bin_buf);
                SEC_CLEAR_STACK(iv_buf);
                return false;
            }
            memset(cipher_data_buf, 0, cipher_data_len + 32);
            memcpy(cipher_data_buf, decode_bin_buf + iv_byte_len, cipher_data_len);
        }
        // Base64解码缓冲区不再使用，提前释放
        SAFE_FREE(decode_bin_buf);

        // ========== 步骤3：派生AES密钥 ==========
        uint8_t aes_key[32] = {0};
        if (!deriveKey(password, aes_key, 32)) {
            SAFE_FREE(cipher_data_buf);
            SEC_CLEAR_STACK(iv_buf);
            SEC_CLEAR_STACK(gcm_tag);
            return false;
        }

        // ========== 步骤4：分配明文输出缓冲区 ==========
        uint8_t* plain_out_buf = (uint8_t*)malloc(cipher_data_len + 1);
        if (plain_out_buf == nullptr) {
            SAFE_FREE(cipher_data_buf);
            SEC_CLEAR_STACK(aes_key);
            SEC_CLEAR_STACK(iv_buf);
            SEC_CLEAR_STACK(gcm_tag);
            return false;
        }
        memset(plain_out_buf, 0, cipher_data_len + 1);
        bool decrypt_success = false;

        // ========== 分模式解密运算 ==========
        if (mode == MODE_GCM) {
            // GCM解密：自动校验Tag，Tag不匹配直接返回非0错误码
            mbedtls_gcm_context gcm_ctx;
            mbedtls_gcm_init(&gcm_ctx);
            int setkey_ret = mbedtls_gcm_setkey(&gcm_ctx, MBEDTLS_CIPHER_ID_AES, aes_key, 256);
            if (setkey_ret == 0) {
                int decrypt_ret = mbedtls_gcm_auth_decrypt(
                    &gcm_ctx,
                    cipher_data_len,
                    iv_buf, iv_byte_len,
                    nullptr, 0,
                    gcm_tag, 16,
                    cipher_data_buf,
                    plain_out_buf
                );
                // 返回0代表Tag校验通过、解密无错误
                if (decrypt_ret == 0) {
                    decrypt_success = true;
                }
            }
            mbedtls_gcm_free(&gcm_ctx);
        } else {
            // CTR解密：加密解密流程完全一致，使用加密密钥
            mbedtls_aes_context aes_ctx;
            mbedtls_aes_init(&aes_ctx);
            int setkey_ret = mbedtls_aes_setkey_enc(&aes_ctx, aes_key, 256);
            if (setkey_ret == 0) {
                uint8_t stream_block[16] = {0};
                size_t nc_offset = 0;
                int decrypt_ret = mbedtls_aes_crypt_ctr(
                    &aes_ctx,
                    cipher_data_len,
                    &nc_offset,
                    iv_buf, stream_block,
                    cipher_data_buf,
                    plain_out_buf
                );
                if (decrypt_ret == 0) {
                    decrypt_success = true;
                }
            }
            mbedtls_aes_free(&aes_ctx);
        }

        // ========== 解密成功：组装输出字符串 ==========
        if (decrypt_success) {
            plain_out_buf[cipher_data_len] = '\0';
            output = String((char*)plain_out_buf);
        }

        // ========== 统一释放所有堆内存、擦除栈敏感数据 ==========
        SAFE_FREE(plain_out_buf);
        SAFE_FREE(cipher_data_buf);
        SEC_CLEAR_STACK(aes_key);
        SEC_CLEAR_STACK(iv_buf);
        SEC_CLEAR_STACK(gcm_tag);

        return decrypt_success;
    }

private:
    /**
     * @brief 使用SHA-256从密码派生32字节AES256密钥
     * 兼容ESP32默认mbedtls配置，无PBKDF2依赖，不会编译报错
     * @param password 用户输入密码字符串
     * @param key 输出32字节密钥缓冲区
     * @param key_len 必须等于32（AES256固定长度）
     * @return true 派生成功
     */
    static bool deriveKey(const String& password, uint8_t* key, size_t key_len) {
        // AES256仅支持32字节密钥
        if (key_len != 32 || key == nullptr) {
            return false;
        }

        mbedtls_sha256_context ctx;
        mbedtls_sha256_init(&ctx);

        // SHA256哈希密码得到32字节密钥
        mbedtls_sha256_starts(&ctx, 0);
        mbedtls_sha256_update(&ctx, (const unsigned char*)password.c_str(), password.length());
        mbedtls_sha256_finish(&ctx, key);

        mbedtls_sha256_free(&ctx);
        return true;
    }
};

#endif