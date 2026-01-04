# E2EE Chat Application - Complete Signal Protocol Implementation

## 项目概述

本项目实现了一个端到端加密（End-to-End Encryption, E2EE）聊天应用，使用**完整版的Signal协议**进行消息加密。这是被WhatsApp、Signal、Facebook Messenger等主流即时通讯应用采用的加密方案。
演示视频：https://www.bilibili.com/video/BV1YTiuBKEf3/?spm_id_from=333.1387.list.card_archive.click&vd_source=fec8c467eaf3b6a6802b38e9c75868e1

### 核心特性

- **X3DH 密钥交换**: Extended Triple Diffie-Hellman，支持异步会话建立
- **Double Ratchet**: 双棘轮算法，提供完美前向保密和入侵恢复
- **Pre-Key Bundle**: 预密钥捆绑包，支持离线用户建立会话
- **Safety Numbers**: 安全数字验证，防止中间人攻击
- **AES-256-GCM**: 认证加密，确保消息机密性和完整性

## 运行方式

```bash
# 安装依赖
pip install cryptography PyQt5

# 终端1: 启动服务器
python Server.py

# 终端2: 启动客户端1 (Alice)
cd Client
python ClientCode.py

# 终端3: 启动客户端2 (Bob)
cd Client
python ClientCode.py
```

## Complete Signal Protocol 架构

### 密码学原语

| 组件 | 算法 | 用途 |
|------|------|------|
| Identity Key | X25519 | 长期身份验证 |
| Signing Key | Ed25519 | 签名 Signed Pre-Key |
| Signed Pre-Key | X25519 + Ed25519 签名 | 中期密钥，定期轮换 |
| One-Time Pre-Key | X25519 | 单次使用，增强前向保密 |
| Ephemeral Key | X25519 | 每次会话唯一 |
| 消息加密 | AES-256-GCM | 认证加密 |
| 密钥派生 | HKDF-SHA256 | 从共享密钥派生会话密钥 |

### X3DH Key Exchange (Extended Triple Diffie-Hellman)

X3DH 是 Signal Protocol 的密钥协商协议，允许两个用户在一方离线的情况下建立共享密钥。

```
Alice (Initiator)                                      Bob (Responder)
─────────────────                                      ─────────────────
IKA (Identity Key)                                     IKB (Identity Key)
EKA (Ephemeral Key)           ──生成──                 SPKB (Signed Pre-Key)
                                                       OPKB (One-Time Pre-Key)

                    X3DH 四重 Diffie-Hellman
                    ─────────────────────────
                    DH1 = ECDH(IKA, SPKB)
                    DH2 = ECDH(EKA, IKB)
                    DH3 = ECDH(EKA, SPKB)
                    DH4 = ECDH(EKA, OPKB)  // 可选，如果有OPK
                    
                    SK = HKDF(DH1 || DH2 || DH3 || DH4)
                           ↓
                    Shared Secret (用于初始化 Double Ratchet)
```

### Double Ratchet Algorithm

Double Ratchet 结合了两种棘轮机制，提供完美前向保密和入侵恢复：

```
┌─────────────────────────────────────────────────────────────────────┐
│                    DOUBLE RATCHET ALGORITHM                         │
├─────────────────────────────────────────────────────────────────────┤
│                                                                     │
│   Root Key (RK)                                                     │
│       │                                                             │
│       ├──────[ DH Ratchet ]──────┐                                  │
│       │                          │                                  │
│       │    DH Output = ECDH(DHs, DHr)                               │
│       │         │                                                   │
│       │         ▼                                                   │
│       │    ┌─────────┐                                              │
│       └───▶│  HKDF  │───▶ New RK                                   │
│            └────┬────┘                                              │
│                 │                                                   │
│                 ▼                                                   │
│         Chain Key (CK)                                              │
│              │                                                      │
│              ├──────[ Symmetric Ratchet ]──────┐                    │
│              │                                 │                    │
│              ▼                                 ▼                    │
│     ┌───────────────┐                  ┌───────────────┐            │
│     │ CK = HMAC(CK) │                  │ MK = HMAC(CK) │            │
│     └───────┬───────┘                  └───────┬───────┘            │
│             │                                  │                    │
│             ▼                                  ▼                    │
│       New Chain Key                       Message Key               │
│                                                                     │
└─────────────────────────────────────────────────────────────────────┘

特性:
• 每条消息都有唯一的密钥 (Forward Secrecy)
• DH 密钥每次通信轮换 (Break-in Recovery)
• 旧密钥被删除，无法解密过去的消息
```

### Pre-Key Bundle 分发

```
┌─────────────┐                  ┌─────────────┐                  ┌─────────────┐
│   Alice     │                  │   Server    │                  │    Bob      │
└──────┬──────┘                  └──────┬──────┘                  └──────┬──────┘
       │                                │                                │
       │                                │ 1. PREKEY_BUNDLE_UPLOAD        │
       │                                │ (IKB, SPKB, OPKs, Signature)   │
       │                                │<───────────────────────────────│
       │                                │                                │
       │ 2. GET_PREKEY_BUNDLE(Bob)      │                                │
       │──────────────────────────────> │                                │
       │                                │                                │
       │ 3. PREKEY_BUNDLE_RESPONSE      │                                │
       │ (Bob's Bundle + 1 OPK)         │                                │
       │<────────────────────────────── │                                │
       │                                │                                │
       │ 4. Verify SPKB signature       │                                │
       │    with IKB                    │                                │
       │                                │                                │
       │ 5. Perform X3DH                │                                │
       │    → Derive Shared Secret      │                                │
       │    → Initialize Ratchet        │                                │
       │                                │                                │
       │ 6. E2EE_MESSAGE                │ 7. Relay (Cannot Decrypt!)     │
       │ (Double Ratchet Encrypted)     │                                │
       │──────────────────────────────> │───────────────────────────────>│
       │                                │                                │
       │                                │                   8. Process   │
       │                                │                   X3DH Header  │
       │                                │                   → Initialize │
       │                                │                   Ratchet as   │
       │                                │                   Bob          │
       │                                │                   → Decrypt    │
```

## Safety Number 验证

Safety Number 用于验证通信双方的身份，防止中间人攻击：

```
╔══════════════════════════════════════════════════════╗
║          SAFETY NUMBER VERIFICATION                  ║
║  Your conversation with: Bob                         ║
╠══════════════════════════════════════════════════════╣
║  1234 5678 9012 3456 7890 1234 5678 9012             ║
║  3456 7890 1234 5678 9012 3456 7890 1234             ║
╚══════════════════════════════════════════════════════╝

使用方法: 在聊天窗口输入 /safety Bob
```

双方应该通过其他渠道（如面对面、电话）验证这个数字是否一致。

## 客户端命令

| 命令 | 说明 |
|------|------|
| `/safety <username>` | 显示与该用户的安全数字 |
| `/connect <username>` | 主动与该用户建立加密会话 |

## JSON 消息结构

### Double Ratchet 加密消息

```json
{
  "type": "E2EE_MESSAGE",
  "version": 3,
  "protocol": "DOUBLE_RATCHET",
  "sender": "Alice",
  "sender_public_key": "base64_identity_key",
  "sender_bundle": {
    "identity_key": "base64_encoded",
    "signed_prekey": "base64_encoded",
    "signed_prekey_id": 1,
    "signed_prekey_signature": "base64_ed25519_sig"
  },
  "messages": {
    "Bob": {
      "header": {
        "dh_public": "base64_ratchet_public_key",
        "previous_chain_length": 0,
        "message_number": 0
      },
      "ciphertext": "base64_aes_gcm_encrypted",
      "nonce": "base64_nonce"
    }
  }
}
```

### Pre-Key Bundle 格式

```json
{
  "identity_key": "base64_x25519_public",
  "identity_signing_key": "base64_ed25519_public",
  "signed_prekey": "base64_x25519_public",
  "signed_prekey_id": 1,
  "signed_prekey_signature": "base64_ed25519_signature",
  "one_time_prekeys": [
    {"key_id": 1, "public_key": "base64_x25519_public"},
    {"key_id": 2, "public_key": "base64_x25519_public"}
  ]
}
```

## 安全特性

### 1. Perfect Forward Secrecy

即使长期密钥泄露，攻击者也无法解密过去的消息：
- 每条消息使用唯一的 Message Key
- Message Key 使用后立即删除
- Chain Key 单向推进，无法逆推

### 2. Break-in Recovery

如果当前会话密钥泄露，新消息仍然安全：
- DH Ratchet 定期轮换 DH 密钥对
- 每次 DH 交换生成新的 Root Key
- 攻击者无法持续窃听

### 3. Asynchronous Communication

支持向离线用户发送加密消息：
- Pre-Key Bundle 存储在服务器
- 发送方可以单方面建立会话
- 接收方上线后可以解密

### 4. Key Verification

防止中间人攻击：
- Signed Pre-Key 带有 Ed25519 签名
- Safety Number 可以带外验证
- 密钥变更时会有警告

## 代码结构

```
Server-Client-ChatApp/
├── Server.py                 # 服务器 - Pre-Key 分发
├── E2EE_README.md           # 本文档
└── Client/
    ├── crypto_utils.py      # 完整 Signal Protocol 实现
    │   ├── SignalConstants  # 协议常量
    │   ├── KeyPair          # X25519 密钥对
    │   ├── SigningKeyPair   # Ed25519 签名密钥对
    │   ├── SignedPreKey     # 签名预密钥
    │   ├── OneTimePreKey    # 一次性预密钥
    │   ├── PreKeyBundle     # 预密钥捆绑包
    │   ├── X3DHKeyAgreement # X3DH 密钥协商
    │   ├── DoubleRatchet    # 双棘轮算法
    │   ├── KeyFingerprint   # 安全数字生成
    │   └── CryptoManager    # 总管理器
    └── ClientCode.py        # 客户端 UI 和网络
```


## 参考文献

1. Marlinspike, M., & Perrin, T. (2016). **The X3DH Key Agreement Protocol**. Signal Foundation.
2. Perrin, T., & Marlinspike, M. (2016). **The Double Ratchet Algorithm**. Signal Foundation.
3. Cohn-Gordon, K., et al. (2017). **A Formal Security Analysis of the Signal Messaging Protocol**. IEEE European Symposium on Security and Privacy.
