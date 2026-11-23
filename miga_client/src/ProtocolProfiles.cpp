#include <windows.h>
#include <sddl.h>
#include <aclapi.h>
#include <wincrypt.h>
#include <shlobj.h>
#include <array>
#include "ProtocolProfiles.h"
#include "nlohmann/json.hpp"
#include <filesystem>
#include <fstream>

namespace {
std::filesystem::path Root() {
    wchar_t value[MAX_PATH]{};
    if (SHGetFolderPathW(nullptr, CSIDL_COMMON_APPDATA, nullptr, SHGFP_TYPE_CURRENT, value) != S_OK)
        return {};
    return std::filesystem::path(value) / L"MIGA" / L"profiles";
}
bool RegularPath(const std::filesystem::path &path) {
    const auto attributes = GetFileAttributesW(path.c_str());
    return attributes != INVALID_FILE_ATTRIBUTES && !(attributes & FILE_ATTRIBUTE_REPARSE_POINT);
}
bool TrustedOwnerSid(PSID owner) {
    return owner && (IsWellKnownSid(owner, WinLocalSystemSid) || IsWellKnownSid(owner, WinBuiltinAdministratorsSid));
}
bool TrustedOwner(const std::filesystem::path &path) {
    PSID owner = nullptr;
    PSECURITY_DESCRIPTOR descriptor = nullptr;
    if (GetNamedSecurityInfoW(path.c_str(), SE_FILE_OBJECT, OWNER_SECURITY_INFORMATION, &owner, nullptr, nullptr, nullptr,
                              &descriptor) != ERROR_SUCCESS)
        return false;
    const bool trusted = TrustedOwnerSid(owner);
    LocalFree(descriptor);
    return trusted;
}
bool ValidId(const std::string &id) {
    return id.size() == 32 && id.find_first_not_of("0123456789abcdef") == std::string::npos;
}
bool Secure(const std::filesystem::path &path, bool directory) {
    PSECURITY_DESCRIPTOR descriptor = nullptr;
    const auto *sddl = directory ? L"D:P(A;OICI;GA;;;SY)(A;OICI;GA;;;BA)" : L"D:P(A;;GA;;;SY)(A;;GA;;;BA)";
    if (!ConvertStringSecurityDescriptorToSecurityDescriptorW(sddl, SDDL_REVISION_1, &descriptor, nullptr))
        return false;
    const bool result =
        SetFileSecurityW(path.c_str(), DACL_SECURITY_INFORMATION | PROTECTED_DACL_SECURITY_INFORMATION, descriptor) != FALSE;
    LocalFree(descriptor);
    return result;
}
}
ProtocolProfiles::~ProtocolProfiles() {
    Stop();
}
void ProtocolProfiles::Start(Status status, Diagnostic diagnostic) {
    Stop();
    status_ = std::move(status);
    diagnostic_ = std::move(diagnostic);
    stopping_.store(false);
    thread_ = std::thread([this] { Serve(); });
}
void ProtocolProfiles::Stop() {
    stopping_.store(true);
    if (thread_.joinable()) {
        while (WaitForSingleObject(thread_.native_handle(), 10) == WAIT_TIMEOUT)
            CancelSynchronousIo(thread_.native_handle());
        thread_.join();
    }
}
bool ProtocolProfiles::Save(const std::string &text, std::string &id) {
    miga::v2::Invitation invitation;
    if (!miga::v2::ParseInvitation(text, invitation))
        return false;
    auto root = Root();
    if (root.empty())
        return false;
    std::error_code error;
    const auto parent = root.parent_path();
    const auto create = [](const std::filesystem::path &path) {
        const auto attributes = GetFileAttributesW(path.c_str());
        if (attributes != INVALID_FILE_ATTRIBUTES)
            return (attributes & FILE_ATTRIBUTE_DIRECTORY) && !(attributes & FILE_ATTRIBUTE_REPARSE_POINT) && TrustedOwner(path) && Secure(path, true);
        PSECURITY_DESCRIPTOR descriptor = nullptr;
        if (!ConvertStringSecurityDescriptorToSecurityDescriptorW(L"D:P(A;OICI;GA;;;SY)(A;OICI;GA;;;BA)", SDDL_REVISION_1, &descriptor,
                                                                  nullptr))
            return false;
        SECURITY_ATTRIBUTES security{sizeof(security), descriptor, FALSE};
        const bool created = CreateDirectoryW(path.c_str(), &security) != FALSE;
        LocalFree(descriptor);
        return created && RegularPath(path) && TrustedOwner(path);
    };
    if (!RegularPath(parent.parent_path()) || !create(parent) || !create(root))
        return false;
    miga::v2::Id random;
    miga::v2::Random(random.data(), random.size());
    const char *hex = "0123456789abcdef";
    for (auto byte : random) {
        id += hex[byte >> 4];
        id += hex[byte & 15];
    }
    DATA_BLOB input{static_cast<DWORD>(text.size()), reinterpret_cast<BYTE *>(const_cast<char *>(text.data()))}, output{};
    if (!CryptProtectData(&input, L"MIGA protocol profile v2", nullptr, nullptr, nullptr,
                          CRYPTPROTECT_LOCAL_MACHINE | CRYPTPROTECT_UI_FORBIDDEN, &output))
        return false;
    const auto temporary = root / (id + ".tmp"), path = root / (id + ".dpapi");
    bool success = false;
    {
        std::ofstream file(temporary, std::ios::binary | std::ios::trunc);
        file.write(reinterpret_cast<char *>(output.pbData), output.cbData);
        file.flush();
        success = file.good();
    }
    SecureZeroMemory(output.pbData, output.cbData);
    LocalFree(output.pbData);
    if (success)
        success = TrustedOwner(temporary) && Secure(temporary, false) && MoveFileExW(temporary.c_str(), path.c_str(), MOVEFILE_WRITE_THROUGH);
    if (!success)
        std::filesystem::remove(temporary, error);
    return success;
}
bool ProtocolProfiles::Load(const std::string &id, miga::v2::Invitation &invitation) {
    if (!ValidId(id))
        return false;
    const auto root = Root();
    if (root.empty())
        return false;
    const auto path = root / (id + ".dpapi");
    if (!RegularPath(root.parent_path()) || !TrustedOwner(root.parent_path()) || !RegularPath(root) || !TrustedOwner(root) ||
        !RegularPath(path) || !TrustedOwner(path))
        return false;
    std::ifstream file(path, std::ios::binary);
    if (!file)
        return false;
    std::array<char, 16385> buffer{};
    file.read(buffer.data(), buffer.size());
    const auto size = file.gcount();
    if (size <= 0 || size > 16384)
        return false;
    std::string encrypted(buffer.data(), static_cast<size_t>(size));
    DATA_BLOB input{static_cast<DWORD>(encrypted.size()), reinterpret_cast<BYTE *>(encrypted.data())}, output{};
    if (!CryptUnprotectData(&input, nullptr, nullptr, nullptr, nullptr, CRYPTPROTECT_UI_FORBIDDEN, &output))
        return false;
    std::string plaintext(reinterpret_cast<char *>(output.pbData), output.cbData);
    SecureZeroMemory(output.pbData, output.cbData);
    LocalFree(output.pbData);
    const auto success = miga::v2::ParseInvitation(plaintext, invitation);
    SecureZeroMemory(plaintext.data(), plaintext.size());
    return success;
}
void ProtocolProfiles::Serve() {
    if (!miga::v2::Initialize())
        return;
    PSECURITY_DESCRIPTOR descriptor = nullptr;
    if (!ConvertStringSecurityDescriptorToSecurityDescriptorW(L"D:P(A;;GA;;;SY)(A;;GA;;;BA)", SDDL_REVISION_1, &descriptor, nullptr))
        return;
    SECURITY_ATTRIBUTES security{sizeof(security), descriptor, FALSE};
    while (!stopping_.load()) {
        HANDLE pipe =
            CreateNamedPipeW(L"\\\\.\\pipe\\MigaProfiles-v2", PIPE_ACCESS_DUPLEX | FILE_FLAG_FIRST_PIPE_INSTANCE,
                             PIPE_TYPE_BYTE | PIPE_READMODE_BYTE | PIPE_WAIT | PIPE_REJECT_REMOTE_CLIENTS, 1, 8192, 8192, 0, &security);
        if (pipe == INVALID_HANDLE_VALUE)
            break;
        if ((ConnectNamedPipe(pipe, nullptr) || GetLastError() == ERROR_PIPE_CONNECTED) && !stopping_.load()) {
            std::string line;
            char byte;
            DWORD count = 0;
            while (!stopping_.load() && line.size() <= 8192 && ReadFile(pipe, &byte, 1, &count, nullptr) && count) {
                if (byte == '\n')
                    break;
                line.push_back(byte);
            }
            nlohmann::json response = {{"ok", false}, {"error", "profile_import_failed"}};
            try {
                auto request = nlohmann::json::parse(line);
                const auto operation = request.value("operation", "");
                if (operation == "import" && request.contains("invitation") && request["invitation"].is_string()) {
                    std::string id;
                    auto invitation = request["invitation"].get<std::string>();
                    if (Save(invitation, id))
                        response = {{"ok", true}, {"profile_id", id}};
                    SecureZeroMemory(invitation.data(), invitation.size());
                } else if (operation == "export") {
                    const auto profile = request.value("profile_id", "");
                    miga::v2::Invitation invitation;
                    if (ValidId(profile) && Load(profile, invitation))
                        response = {{"ok", true}, {"invitation", miga::v2::FormatInvitation(invitation)}};
                } else if (operation == "diagnostics") {
                    const auto profile = request.value("profile_id", "");
                    const auto result = ValidId(profile) && diagnostic_ ? diagnostic_(profile) : std::string();
                    response = result.empty() ? nlohmann::json{{"ok", false}, {"error", "diagnostics_unavailable"}} : nlohmann::json::parse(result);
                } else if (operation == "status") {
                    const auto profile = request.value("profile_id", "");
                    const auto state = ValidId(profile) && status_ ? status_(profile) : std::string();
                    if (!state.empty())
                        response = {{"ok", true}, {"state", state}};
                    else
                        response = {{"ok", false}, {"error", "profile_not_configured"}};
                }
            } catch (...) {
            }
            SecureZeroMemory(line.data(), line.size());
            auto text = response.dump() + "\n";
            WriteFile(pipe, text.data(), static_cast<DWORD>(text.size()), &count, nullptr);
            SecureZeroMemory(text.data(), text.size());
            if (response.contains("invitation") && response["invitation"].is_string()) {
                auto& invitationText = response["invitation"].get_ref<std::string&>();
                SecureZeroMemory(invitationText.data(), invitationText.size());
            }
            response.clear();
        }
        CloseHandle(pipe);
    }
    LocalFree(descriptor);
}
