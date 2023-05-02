#include <functional>
#include <string>
#include <mutex>
#include <thread>
#include <string_view>
#include <atomic>
#include <signal.h>
#include <execinfo.h>
#include <filesystem>
#include <chrono>
#include "../core/logger.hpp"
#include "../core/crypto.hpp"
#include "../core/host_manager.hpp"
#include "../core/helpers.hpp"
#include "../core/api.hpp"
#include "../core/crypto.hpp"
#include "../core/config.hpp"
#include "../core/logger.hpp"
#include "request_manager.hpp"
#include "server.hpp"
#include "handlers.hpp"

using namespace std;

namespace {
    std::function<void(int)> shutdown_handler;
    void signal_handler(int signal) {

        void* array[10];
        size_t size;

        if (signal == SIGTERM || signal == SIGSEGV) {

            // get void*'s for all entries on the stack
            size = backtrace(array, 10);

            // print out all the frames to stderr
            std::cerr << "Error: signal " << signal << std::endl;
            backtrace_symbols_fd(array, size, STDERR_FILENO);

            Logger::logError(RED + "[FATAL]" + RESET, "Error: signal " + std::to_string(signal));

        }

        shutdown_handler(signal);
        exit(0);
    }
}

void PandaniteServer::run(json config) {
    srand(time(0));

    std::filesystem::path data{ "data" };

    if (!std::filesystem::exists(data)) {
        Logger::logStatus("Creating data directory...");
        try {
            std::filesystem::create_directory(data);
        }
        catch (std::exception& e) {
            std::cout << e.what() << std::endl;
        }
    }

    Logger::logStatus("Starting Server Version: ");
    HostManager hosts(config);

    RequestManager manager(hosts);

    // start downloading headers from peers
    hosts.syncHeadersWithPeers();

    // start pinging other peers about ourselves
    hosts.startPingingPeers();

    shutdown_handler = [&](int signal) {
        Logger::logStatus("Shutting down server.");
        manager.exit();
        Logger::logStatus("FINISHED");
    };

    signal(SIGINT, signal_handler);
    signal(SIGQUIT, signal_handler);
    signal(SIGTERM, signal_handler);
    signal(SIGSEGV, signal_handler);

    if (config["rateLimiter"] == false) manager.enableRateLimiting(false);

    Logger::logStatus("RequestManager ready...");
    Logger::logStatus("Server Ready.");

    uWS::App app;

    setupRoutes(app, manager, config);

    std::function<void()> listen_function = [&]() {
        app.listen((int)config["port"], [&hosts](auto *token) {
            Logger::logStatus("==========================================");
            Logger::logStatus("Started server: " + hosts.getAddress());
            Logger::logStatus("==========================================");
        }).run();
    };

    // Start listening and run the server
    std::atomic<bool> running(true);
    while (running) {
        try {
            listen_function();
        }
        catch (const std::exception& e) {
            // Log the error and wait for a few seconds before restarting the server
            Logger::logError(RED + "[ERROR]" + RESET, e.what());
            Logger::logStatus("Restarting server in 10 seconds...");
            std::this_thread::sleep_for(std::chrono::seconds(10));
            continue;
        }
    }
}

