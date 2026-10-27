#pragma once

#include <string>
#include <string_view>
#include <cstring>

inline std::string LogValue(std::string_view value) {
    static constexpr char hex[] = "0123456789abcdef";
    std::string result = "\"";
    for (unsigned char c : value) {
        switch (c) {
        case '\\': result += "\\\\"; break;
        case '"': result += "\\\""; break;
        case '\n': result += "\\n"; break;
        case '\r': result += "\\r"; break;
        case '\t': result += "\\t"; break;
        default:
            if (c < 32 || c == 127) {
                result += "\\x";
                result += hex[c >> 4];
                result += hex[c & 15];
            }
            else result += static_cast<char>(c);
        }
    }
    result += '"';
    return result;
}

inline std::string LogErrno(int code) {
#ifdef _WIN32
    char message[256]{};
    strerror_s(message, sizeof(message), code);
    return " errno=" + std::to_string(code) + " error=" + LogValue(message);
#else
    return " errno=" + std::to_string(code) + " error=" + LogValue(std::strerror(code));
#endif
}
