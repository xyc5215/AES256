#include "AES256.h"

void setup() {
    Serial.begin(115200);
    delay(1000);
    
    String plaintext = "Hello, ESP32-S3! 这是AES-256加密测试。";
    String password = "MySecretPassword123!";
    String encrypted;
    String decrypted;
    
    // ========== GCM模式测试（推荐，带防篡改校验） ==========
    Serial.println("==================== GCM 模式测试 ====================");
    // 每次测试清空输出字符串，防止上一轮残留干扰
    encrypted.clear();
    decrypted.clear();
    if (AES256::encrypt(plaintext, password, AES256::MODE_GCM, encrypted)) {
        Serial.println("✅ GCM 加密成功！");
        Serial.println("Base64密文：" + encrypted);
        
        if (AES256::decrypt(encrypted, password, AES256::MODE_GCM, decrypted)) {
            Serial.println("✅ GCM 解密成功！");
            Serial.println("还原明文：" + decrypted);
        } else {
            Serial.println("❌ GCM 解密失败：密码错误/密文篡改/数据损坏");
        }
    } else {
        Serial.println("❌ GCM 加密失败：内存不足/随机数生成异常");
    }

    delay(1500);
    
    // ========== CTR模式测试（无完整性校验，仅基础加密） ==========
    Serial.println("\n==================== CTR 模式测试 ====================");
    encrypted.clear();
    decrypted.clear();
    if (AES256::encrypt(plaintext, password, AES256::MODE_CTR, encrypted)) {
        Serial.println("✅ CTR 加密成功！");
        Serial.println("Base64密文：" + encrypted);
        
        if (AES256::decrypt(encrypted, password, AES256::MODE_CTR, decrypted)) {
            Serial.println("✅ CTR 解密成功！");
            Serial.println("还原明文：" + decrypted);
        } else {
            Serial.println("❌ CTR 解密失败：数据损坏/模式不匹配");
        }
    } else {
        Serial.println("❌ CTR 加密失败：内存不足/参数错误");
    }
}

void loop() {
    // 无循环任务
}