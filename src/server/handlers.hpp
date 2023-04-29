#pragma once

#include <App.h>
#include <HttpResponse.h>
#include <functional>
#include <string>
#include <mutex>
#include <thread>
#include <string_view>
#include <atomic>
#include <signal.h>
#include <execinfo.h>
#include <filesystem>
#include "../core/logger.hpp"
#include "../core/crypto.hpp"
#include "../core/host_manager.hpp"
#include "../core/helpers.hpp"
#include "../core/api.hpp"
#include "../core/crypto.hpp"
#include "../core/config.hpp"
#include "../core/logger.hpp"
#include "request_manager.hpp"

using json = nlohmann::json;

auto corsHandler(RequestManager &manager);
auto logsHandler(RequestManager &manager);
auto nameHandler(RequestManager &manager, const json &config);
auto statsHandler(RequestManager &manager);
auto totalWorkHandler(RequestManager &manager);
auto peerHandler(RequestManager &manager);
auto blockCountHandler(RequestManager &manager);
auto txJsonHandler(RequestManager &manager);
auto blockHandler(RequestManager &manager);
auto mineStatusHandler(RequestManager &manager);
auto ledgerHandler(RequestManager &manager);
auto walletHandler(RequestManager &manager);
auto ledgerHandlerDeprecated(RequestManager &manager);
auto createWalletHandler(RequestManager &manager);
auto createTransactionHandler(RequestManager &manager);
auto addPeerHandler(RequestManager &manager);
auto submitHandler(RequestManager &manager);
auto getTxHandler(RequestManager &manager);
auto supplyHandler(RequestManager &manager);
auto mineHandler(RequestManager &manager);
auto syncHandlerDeprecated(RequestManager &manager);
auto blockHeaderHandlerDeprecated(RequestManager &manager);
auto blockHandlerDeprecated(RequestManager &manager);
auto mineStatusHandlerDeprecated(RequestManager &manager);
auto syncHandler(RequestManager &manager);
auto blockHeaderHandler(RequestManager &manager);
auto addTransactionHandler(RequestManager &manager);
auto addTransactionJSONHandler(RequestManager &manager);
auto verifyTransactionHandler(RequestManager &manager);
auto getNetworkHashrateHandler(RequestManager &manager);
auto mainHandler(RequestManager &manager);

void setupRoutes(uWS::App &app, RequestManager &manager, const json &config);