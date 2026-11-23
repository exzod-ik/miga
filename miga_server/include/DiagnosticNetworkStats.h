#pragma once

#include <nlohmann/json.hpp>
#include <cstdint>

class DiagnosticNetworkStats {
public:
    using Json = nlohmann::json;
    static Json Capture(int socket, uint32_t address);
    static Json Difference(const Json& before, const Json& after);
};
