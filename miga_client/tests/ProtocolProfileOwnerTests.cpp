#include "../src/ProtocolProfiles.cpp"
#include <cassert>
#include <iostream>

int main() {
    assert(miga::v2::Initialize());
    miga::v2::Invitation invitation;
    invitation.host = "vpn.example.com";
    invitation.portStart = 10000;
    invitation.portEnd = 15000;
    for (size_t index = 0; index < invitation.serverKey.size(); ++index) {
        invitation.serverKey[index] = static_cast<uint8_t>(index);
        invitation.serverSecret[index] = static_cast<uint8_t>(index + 1);
        invitation.clientSecret[index] = static_cast<uint8_t>(index + 2);
    }
    const auto text = miga::v2::FormatInvitation(invitation);
    miga::v2::Invitation restored;
    assert(miga::v2::ParseInvitation(text, restored));
    assert(restored.host == invitation.host && restored.portStart == invitation.portStart && restored.portEnd == invitation.portEnd);
    assert(restored.serverKey == invitation.serverKey && restored.serverSecret == invitation.serverSecret && restored.clientId == invitation.clientId && restored.clientSecret == invitation.clientSecret);
    assert(!ProtocolProfiles::Load("../invalid", restored));
    assert(!ProtocolProfiles::Load("00000000000000000000000000000000", restored));
    std::array<uint8_t, SECURITY_MAX_SID_SIZE> system{}, administrators{};
    DWORD systemSize = static_cast<DWORD>(system.size()), administratorsSize = static_cast<DWORD>(administrators.size());
    assert(CreateWellKnownSid(WinLocalSystemSid, nullptr, system.data(), &systemSize));
    assert(CreateWellKnownSid(WinBuiltinAdministratorsSid, nullptr, administrators.data(), &administratorsSize));
    assert(TrustedOwnerSid(system.data()) && TrustedOwnerSid(administrators.data()) && !TrustedOwnerSid(nullptr));
    HANDLE token = nullptr;
    assert(OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &token));
    DWORD required = 0;
    GetTokenInformation(token, TokenUser, nullptr, 0, &required);
    std::vector<uint8_t> bytes(required);
    assert(GetTokenInformation(token, TokenUser, bytes.data(), required, &required));
    CloseHandle(token);
    const auto user = reinterpret_cast<TOKEN_USER*>(bytes.data())->User.Sid;
    assert(!TrustedOwnerSid(user));
    const auto directory = std::filesystem::absolute(std::filesystem::path("Build/profile-owner-tests") /
        (std::to_string(GetCurrentProcessId()) + "-" + std::to_string(GetTickCount64())));
    std::filesystem::create_directories(directory.parent_path());
    EXPLICIT_ACCESSW permission{};
    permission.grfAccessPermissions = GENERIC_ALL;
    permission.grfAccessMode = SET_ACCESS;
    permission.Trustee.TrusteeForm = TRUSTEE_IS_SID;
    permission.Trustee.TrusteeType = TRUSTEE_IS_USER;
    permission.Trustee.ptstrName = reinterpret_cast<LPWSTR>(user);
    PACL acl = nullptr;
    assert(SetEntriesInAclW(1, &permission, nullptr, &acl) == ERROR_SUCCESS);
    SECURITY_DESCRIPTOR descriptor{};
    assert(InitializeSecurityDescriptor(&descriptor, SECURITY_DESCRIPTOR_REVISION));
    assert(SetSecurityDescriptorOwner(&descriptor, user, FALSE));
    assert(SetSecurityDescriptorDacl(&descriptor, TRUE, acl, FALSE));
    SECURITY_ATTRIBUTES security{sizeof(security), &descriptor, FALSE};
    assert(CreateDirectoryW(directory.c_str(), &security));
    const auto file = directory / L"profile.dpapi";
    const auto handle = CreateFileW(file.c_str(), GENERIC_WRITE, 0, &security, CREATE_NEW, FILE_ATTRIBUTE_NORMAL, nullptr);
    assert(handle != INVALID_HANDLE_VALUE);
    CloseHandle(handle);
    for (const auto& path : {file, directory}) {
        assert(RegularPath(path) && !TrustedOwner(path));
        assert(Secure(path, path == directory));
        assert(!TrustedOwner(path));
        assert(SetNamedSecurityInfoW(const_cast<wchar_t*>(path.c_str()), SE_FILE_OBJECT,
            DACL_SECURITY_INFORMATION | PROTECTED_DACL_SECURITY_INFORMATION, nullptr, nullptr, acl, nullptr) == ERROR_SUCCESS);
    }
    LocalFree(acl);
    assert(DeleteFileW(file.c_str()));
    assert(RemoveDirectoryW(directory.c_str()));
    std::cout << "Protocol profile owner regression tests passed" << std::endl;
}
