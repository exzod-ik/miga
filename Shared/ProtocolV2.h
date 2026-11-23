#pragma once
#include <array>
#include <cstdint>
#include <memory>
#include <string>
#include <vector>

namespace miga::v2 {
using Bytes = std::vector<uint8_t>;
using Key = std::array<uint8_t, 32>;
using Id = std::array<uint8_t, 16>;
using Prefix = std::array<uint8_t, 4>;
constexpr size_t MaxControl = 1200;
constexpr size_t MaxInner = 65499;
constexpr uint64_t DataProbeCapability = uint64_t{1} << 63;
enum class Operation : uint16_t { Hello = 1, HelloReply, Open, OpenReply, Bind, Ready, AddAddress, AddressReply, Resume, Close, Status, Error, DiagnosticOpen, DiagnosticReply };
struct Invitation {
    ~Invitation();
    std::string host;
    uint16_t portStart = 10000, portEnd = 15000;
    Key serverKey{}, serverSecret{}, clientSecret{};
    Id clientId{};
};
struct Message { Operation operation = Operation::Error; Id request{}; Bytes body; };
struct SessionKeys {
    ~SessionKeys();
    Key dataC2S{}, dataS2C{}, controlC2S{}, controlS2C{}, resume{};
    Prefix prefixC2S{}, prefixS2C{};
};
struct Hello { Id client{}; uint64_t time = 0; Bytes noise; Key proof{}; };
struct OpenReply { ~OpenReply(); Id session{}; Key secret{}, challenge{}; uint16_t port = 0; std::vector<std::pair<uint32_t, uint32_t>> addresses; };
struct ReplayWindow {
    uint64_t highest = 0, bitmap = 0;
    bool Accept(uint64_t counter);
};
bool Initialize();
void Random(uint8_t* output, size_t length);
std::string Base64(const uint8_t* data, size_t length);
bool Unbase64(const std::string& value, Bytes& result);
bool ParseInvitation(const std::string& text, Invitation& invitation);
std::string FormatInvitation(const Invitation& invitation);
Key Hmac(const Key& key, const uint8_t* data, size_t length);
Bytes Hkdf(const Key& secret, const std::string& label, const Bytes& context, size_t length);
Key ScheduleKey(const Key& secret);
Key EnvelopeKey(const Key& secret);
uint16_t DailyPort(const Key& schedule, uint64_t day, uint16_t start, uint16_t end);
SessionKeys DeriveSession(const Key& secret, const Key& handshakeHash, const Id& client, const Id& session);
Bytes EncodeMessage(const Message& message);
bool DecodeMessage(const Bytes& bytes, Message& message);
Bytes Seal(const Key& key, const Bytes& plaintext, size_t minimum = 384, size_t maximum = 768);
bool Unseal(const Key& key, const uint8_t* data, size_t length, Bytes& plaintext);
Bytes EncodeHello(const Hello& hello);
bool DecodeHello(const Bytes& body, Hello& hello);
Key HelloProof(const Key& secret, const Id& client, uint64_t time, const Id& request, const Key& serverKey, const Bytes& noise);
Bytes EncodeOpenReply(const OpenReply& reply);
bool DecodeOpenReply(const Bytes& body, OpenReply& reply);
Bytes SealControl(const Key& envelope, const Key& control, const Id& session, uint64_t counter, const Message& message);
bool UnsealControl(const Key& envelope, const Key& control, const uint8_t* data, size_t length, Id& session, uint64_t& counter, Message& message);
size_t EncryptDataInto(const Key& key, const Prefix& prefix, const uint8_t* packet, size_t length, uint8_t* output, size_t capacity, size_t maximumPayload = 65507);
bool EncryptData(const Key& key, const Prefix& prefix, const uint8_t* packet, size_t length, Bytes& output, size_t maximumPayload = 65507);
bool EncryptKeepalive(const Key& key, const Prefix& prefix, Bytes& output, size_t maximumPayload = 65507);
bool EncryptDataProbe(const Key& key, const Prefix& prefix, const Id& token, bool reply, Bytes& output);
bool ReadDataProbe(const Key& key, const Bytes& plaintext, bool reply, Id& token);
bool DecryptData(const Key& key, const Prefix& prefix, const uint8_t* packet, size_t length, Bytes& output);
bool ValidateInner(const uint8_t* packet, size_t available, size_t& length, bool& keepalive);
bool TranslateAddress(uint8_t* packet, size_t length, uint32_t oldAddress, uint32_t newAddress, bool source);
void Put16(Bytes& bytes, uint16_t value);
void Put32(Bytes& bytes, uint32_t value);
void Put64(Bytes& bytes, uint64_t value);
uint16_t Get16(const uint8_t* bytes);
uint32_t Get32(const uint8_t* bytes);
uint64_t Get64(const uint8_t* bytes);
class NoiseHandshake {
public:
    NoiseHandshake();
    ~NoiseHandshake();
    NoiseHandshake(const NoiseHandshake&) = delete;
    NoiseHandshake& operator=(const NoiseHandshake&) = delete;
    bool Start(bool initiator, const Key& serverKey, const Key* privateKey = nullptr);
    bool Write(const Bytes& payload, Bytes& message);
    bool Read(const Bytes& message, Bytes& payload);
    bool Complete() const;
    bool Hash(Key& hash) const;
    static bool GenerateKeypair(Key& privateKey, Key& publicKey);
private:
    void* state_ = nullptr;
};
}
