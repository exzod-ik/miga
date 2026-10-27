#include "Logger.h"
#include <cassert>
#include <filesystem>
#include <sstream>
#include <thread>
#include <vector>

int main() {
    assert(LogValue("") == "\"\"");
    assert(LogValue("app name.exe") == "\"app name.exe\"");
    assert(LogValue("C:\\path\"\n\r\t") == "\"C:\\\\path\\\"\\n\\r\\t\"");
    assert(LogValue(std::string("\0\x01\x7f", 3)) == "\"\\x00\\x01\\x7f\"");
    assert(LogValue("name=value") == "\"name=value\"");
    const auto previous = std::filesystem::current_path();
    const auto temporary = previous / "Build" / "tests" /
        ("logger-" + std::to_string(std::chrono::steady_clock::now().time_since_epoch().count()));
    std::filesystem::create_directories(temporary);
    std::filesystem::current_path(temporary);
    std::ostringstream output;
    auto* console = std::cout.rdbuf(output.rdbuf());
    {
        Logger logger;
        logger.enable(LOGGER_LEVEL_ERROR);
        int evaluations = 0;
        logger.logLazy(LOGGER_LEVEL_DEBUG, [&] { ++evaluations; return "hidden-debug"; });
        logger.logLazy(LOGGER_LEVEL_INFO, [&] { ++evaluations; return "hidden-info"; });
        assert(evaluations == 0);
        assert(logger.isEnabled(LOGGER_LEVEL_ERROR));
        assert(!logger.isEnabled(LOGGER_LEVEL_INFO));
        logger.logLazy(LOGGER_LEVEL_ERROR, [&] { ++evaluations; return "visible-error"; });
        assert(evaluations == 1);
        std::ifstream file("session.log");
        std::string line;
        assert(std::getline(file, line) && line.find("visible-error") != std::string::npos);
        file.close();
        logger.logLazy(LOGGER_LEVEL_WARNING, [&] { ++evaluations; return "hidden-warning"; });
        assert(evaluations == 1);
        logger.enable(LOGGER_LEVEL_WARNING);
        assert(logger.isEnabled(LOGGER_LEVEL_ERROR));
        assert(logger.isEnabled(LOGGER_LEVEL_WARNING));
        assert(!logger.isEnabled(LOGGER_LEVEL_INFO));
        logger.logLazy(LOGGER_LEVEL_INFO, [] { return "hidden-info-warning-level"; });
        logger.recordDelay(NetworkWarning::BatchProcessing, std::chrono::steady_clock::now());
        logger.flushWarnings();
        file.open("session.log");
        assert(!std::getline(file, line));
        file.close();
        std::vector<std::thread> recorders;
        for (int i = 0; i < 4; ++i)
            recorders.emplace_back([&] {
                for (int j = 0; j < 1000; ++j)
                    logger.recordWarning(NetworkWarning::BatchAge, 150);
            });
        for (auto& recorder : recorders) recorder.join();
        logger.flushWarnings();
        logger.flushWarnings();
        file.open("session.log");
        assert(std::getline(file, line));
        assert(line.find("WARNING: batch_age_after_receive count=4000 total_value=600000") != std::string::npos);
        assert(line.find("value_unit=ms window=approximate") != std::string::npos);
        assert(!std::getline(file, line));
        file.close();
        logger.recordWarning(NetworkWarning::ReceiveBufferWait, 182);
        logger.recordWarning(NetworkWarning::ReceiveEventQueueWait, 125);
        logger.flushWarnings();
        assert(output.str().find("receive_buffer_wait count=1 total_value=182") != std::string::npos);
        assert(output.str().find("receive_event_queue_wait count=1 total_value=125") != std::string::npos);
        logger.recordWarning(NetworkWarning::LargeTunnelPacket, 1600);
        logger.recordWarning(NetworkWarning::RoutingDrop);
        logger.flushWarnings();
        assert(output.str().find("total_value=1600 value_unit=bytes window=approximate") != std::string::npos);
        assert(output.str().find("routing_drop count=1 total_value=0 value_unit=none window=approximate") != std::string::npos);
        logger.log(LOGGER_LEVEL_WARNING, "format_probe value=" + LogValue("name\nERROR: forged=1"));
        assert(output.str().find("format_probe value=\"name\\nERROR: forged=1\"") != std::string::npos);
        assert(output.str().find("\nERROR: forged=1") == std::string::npos);
        logger.enable(LOGGER_LEVEL_DEBUG);
        std::vector<std::thread> threads;
        for (int i = 0; i < 4; ++i)
            threads.emplace_back([&] {
                for (int j = 0; j < 100; ++j)
                    logger.logLazy(LOGGER_LEVEL_DEBUG, [] { return "concurrent-debug"; });
            });
        for (auto& thread : threads) thread.join();
        file.open("session.log");
        int count = 0;
        while (std::getline(file, line)) {
            assert(line.find("concurrent-debug") != std::string::npos);
            ++count;
        }
        assert(count == 400);
        file.close();
        logger.enable(LOGGER_LEVEL_NONE);
        logger.logLazy(LOGGER_LEVEL_ERROR, [&] { ++evaluations; return "hidden-error"; });
        assert(evaluations == 1);
    }
    std::cout.rdbuf(console);
    assert(output.str().find("hidden-") == std::string::npos);
    std::filesystem::current_path(previous);
    std::filesystem::remove(temporary / "session.log");
    std::filesystem::remove(temporary);
    std::cout << "Logger tests passed\n";
}
