#include <jni.h>
#include "../../../../../miga_client/include/ProtocolV2Session.h"
#include "ProtocolV2Packets.h"
#include <memory>
#include <algorithm>

namespace {
using namespace miga::v2;
struct Context {
    int data = -1;
    std::unique_ptr<ProtocolV2Session> session;
    Ipv4Reassembler fragments;
    Id probe{};
    uint64_t probeGeneration = 0;
    ~Context() { session.reset(); if (data >= 0) close(data); }
};
Context* Get(jlong handle) { return reinterpret_cast<Context*>(handle); }
Bytes Read(JNIEnv* env, jbyteArray input) {
    if (!input) return {};
    const auto size = env->GetArrayLength(input);
    if (size <= 0 || size > 65535) return {};
    Bytes result(size);
    env->GetByteArrayRegion(input, 0, size, reinterpret_cast<jbyte*>(result.data()));
    return result;
}
jbyteArray Write(JNIEnv* env, const Bytes& bytes) {
    if (bytes.empty()) return nullptr;
    auto result = env->NewByteArray(static_cast<jsize>(bytes.size()));
    if (result) env->SetByteArrayRegion(result, 0, static_cast<jsize>(bytes.size()), reinterpret_cast<const jbyte*>(bytes.data()));
    return result;
}
}
extern "C" JNIEXPORT jlong JNICALL Java_org_miga_android_ProtocolV2Native_open(JNIEnv* env, jobject, jstring text, jint ip, jint data, jint control) {
    try {
        if (!text || !miga::v2::Initialize()) return 0;
        const char* characters = env->GetStringUTFChars(text, nullptr);
        if (!characters) return 0;
        std::string encoded(characters);
        env->ReleaseStringUTFChars(text, characters);
        Invitation invitation;
        if (!ParseInvitation(encoded, invitation)) return 0;
        auto context = std::make_unique<Context>();
        context->data = dup(data);
        if (context->data < 0) return 0;
        context->session = std::make_unique<ProtocolV2Session>(invitation, htonl(static_cast<uint32_t>(ip)), context->data);
        context->session->SetMaximumPayload(1408);
        const auto controlCopy = dup(control);
        if (controlCopy < 0 || !context->session->Start(0, controlCopy)) return 0;
        return reinterpret_cast<jlong>(context.release());
    } catch (...) { return 0; }
}
extern "C" JNIEXPORT jint JNICALL Java_org_miga_android_ProtocolV2Native_port(JNIEnv*, jobject, jlong handle) {
    auto* context = Get(handle);
    const auto state = context ? context->session->Snapshot() : nullptr;
    return state ? state->port : 0;
}
extern "C" JNIEXPORT jboolean JNICALL Java_org_miga_android_ProtocolV2Native_sendStale(JNIEnv*, jobject, jlong handle) {
    auto* context = Get(handle);
    const auto state = context ? context->session->Snapshot() : nullptr;
    return state && context->session->AndroidSendStale(*state);
}
extern "C" JNIEXPORT void JNICALL Java_org_miga_android_ProtocolV2Native_dataSent(JNIEnv*, jobject, jlong handle, jint port) {
    if (auto* context = Get(handle)) context->session->MarkAndroidDataSent(static_cast<uint16_t>(port));
}
extern "C" JNIEXPORT jlong JNICALL Java_org_miga_android_ProtocolV2Native_probeGeneration(JNIEnv*, jobject, jlong handle) {
    auto* context = Get(handle);
    const auto state = context ? context->session->Snapshot() : nullptr;
    return state && state->dataProbeSupported ? static_cast<jlong>(state->generation) : 0;
}
extern "C" JNIEXPORT void JNICALL Java_org_miga_android_ProtocolV2Native_sendProbe(JNIEnv*, jobject, jlong handle, jlong generation, jint ip) {
    try {
        auto* context = Get(handle);
        const auto state = context ? context->session->Snapshot() : nullptr;
        if (!state || !state->dataProbeSupported || state->generation != static_cast<uint64_t>(generation)) return;
        Random(context->probe.data(), context->probe.size());
        context->probeGeneration = 0;
        Bytes packet;
        if (!EncryptDataProbe(state->keys.dataC2S, state->keys.prefixC2S, context->probe, false, packet)) return;
        sockaddr_in endpoint{};
        endpoint.sin_family = AF_INET;
        endpoint.sin_addr.s_addr = htonl(static_cast<uint32_t>(ip));
        endpoint.sin_port = htons(state->port);
        if (sendto(context->data, packet.data(), packet.size(), MSG_DONTWAIT,
                   reinterpret_cast<sockaddr*>(&endpoint), sizeof(endpoint)) == static_cast<ssize_t>(packet.size()))
            context->probeGeneration = state->generation;
    } catch (...) {}
}
extern "C" JNIEXPORT jbyteArray JNICALL Java_org_miga_android_ProtocolV2Native_encode(JNIEnv* env, jobject, jlong handle, jbyteArray input, jint port) {
    try {
        auto* context = Get(handle);
        if (!context) return nullptr;
        auto packet = Read(env, input);
        size_t actual = 0; bool keepalive = false;
        if (!ValidateInner(packet.data(), packet.size(), actual, keepalive) || keepalive || actual != packet.size()) return nullptr;
        const auto original = Get32(packet.data() + 12);
        const auto state = context->session->Snapshot();
        if (!state || !state->addresses.count(original)) { context->session->RequestAddress(original); return nullptr; }
        if (port != state->port || !TranslateAddress(packet.data(), packet.size(), original, state->addresses.at(original), true)) return nullptr;
        Bytes output;
        if (!EncryptData(state->keys.dataC2S, state->keys.prefixC2S, packet.data(), packet.size(), output, 1408)) return nullptr;
        return Write(env, output);
    } catch (...) { return nullptr; }
}
extern "C" JNIEXPORT jbyteArray JNICALL Java_org_miga_android_ProtocolV2Native_decode(JNIEnv* env, jobject, jlong handle, jbyteArray input, jint port) {
    try {
        auto* context = Get(handle);
        if (!context) return nullptr;
        const auto state = context->session->Snapshot();
        if (!state || state->port != port) return nullptr;
        auto packet = Read(env, input);
        Bytes output;
        if (!DecryptData(state->keys.dataS2C, state->keys.prefixS2C, packet.data(), packet.size(), output)) return nullptr;
        if ((output[0] >> 4) != 4) {
            Id token{};
            if (context->probeGeneration != state->generation ||
                !ReadDataProbe(state->keys.dataS2C, output, true, token) || token != context->probe) return nullptr;
            context->probeGeneration = 0;
            return env->NewByteArray(0);
        }
        if (output.size() < 20) return nullptr;
        const auto address = Get32(output.data() + 16);
        const auto found = std::find_if(state->addresses.begin(), state->addresses.end(), [address](const auto& item) { return item.second == address; });
        if (found == state->addresses.end() || !TranslateAddress(output.data(), output.size(), address, found->first, false)) return nullptr;
        if (Get16(output.data() + 6) & 0x3fff) {
            Bytes joined;
            std::string identity(reinterpret_cast<const char*>(state->session.data()), state->session.size());
            identity.append(reinterpret_cast<const char*>(&state->generation), sizeof(state->generation));
            if (context->fragments.Add(output.data(), output.size(), joined, identity) != Ipv4Reassembler::Result::Complete) return nullptr;
            output = std::move(joined);
        }
        return Write(env, output);
    } catch (...) { return nullptr; }
}
extern "C" JNIEXPORT void JNICALL Java_org_miga_android_ProtocolV2Native_close(JNIEnv*, jobject, jlong handle) { delete Get(handle); }
