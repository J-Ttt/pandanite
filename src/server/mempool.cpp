#include <iostream>
#include <sstream>
#include <future>
#include <mutex>
#include <set>
#include <vector>
#include <cstring>
#include <cstdint>
#include <cstdlib>
#include "../core/logger.hpp"
#include "../core/api.hpp"
#include "mempool.hpp"
#include "blockchain.hpp"

#define TX_BRANCH_FACTOR 10
#define MIN_FEE_TO_ENTER_MEMPOOL 1

MemPool::MemPool(HostManager& h, BlockChain& b) : hosts(h), blockchain(b) {
    shutdown = false;
}

MemPool::~MemPool() {
    shutdown = true;
}

void MemPool::mempool_sync() {
    while (!shutdown) {
        std::this_thread::sleep_for(std::chrono::milliseconds(100));

        std::vector<Transaction> txs;
        {
            std::unique_lock<std::mutex> lock(toSend_mutex);
            if (toSend.empty()) {
                continue;
            }
            txs = std::vector<Transaction>(std::make_move_iterator(toSend.begin()), std::make_move_iterator(toSend.end()));
            toSend.clear();
        }

        std::vector<Transaction> invalidTxs;
        {
            std::unique_lock<std::mutex> lock(mempool_mutex);
            for (auto it = transactionQueue.begin(); it != transactionQueue.end(); ) {
                try {
                    ExecutionStatus status = blockchain.verifyTransaction(*it);
                    if (status != SUCCESS) {
                        invalidTxs.push_back(*it);
                        it = transactionQueue.erase(it);
                    } else {
                        ++it;
                    }
                } catch (const std::exception& e) {
                    std::cout << "Caught exception: " << e.what() << '\n';
                    invalidTxs.push_back(*it);
                    it = transactionQueue.erase(it);
                }
            }
        }

        if (transactionQueue.empty()) {
            continue;
        }
        
        std::vector<std::future<bool>> reqs;
        std::set<std::string> neighbors = hosts.sampleFreshHosts(TX_BRANCH_FACTOR);
        bool all_sent = true;

        for (auto neighbor : neighbors) {
            for (const auto& tx : txs) {
                reqs.push_back(std::async(std::launch::async, [neighbor, tx]() -> bool {
                    try {
                        sendTransaction(neighbor, tx);
                        return true;
                    } catch (...) {
                        Logger::logError("MemPool::mempool_sync", "Could not send tx to " + neighbor);
                        return false;
                    }
                }));
            }
        }

        for (auto& req : reqs) {
            if (!req.get()) {
                all_sent = false;
            }
        }

        if (!all_sent) {
            std::unique_lock<std::mutex> lock(toSend_mutex);
            for (const auto& tx : txs) {
                toSend.push_back(tx);
            }
        }
    }
}

void MemPool::sync() {
    syncThread.push_back(std::thread(&MemPool::mempool_sync, this));
}

ExecutionStatus MemPool::addTransaction(const Transaction& transaction) {
    std::unique_lock<std::mutex> lock(mempool_mutex);
    transactionQueue.insert(transaction);
    return blockchain.verifyTransaction(transaction);
}

std::vector<Transaction> MemPool::getTransactions(size_t count) const {
    std::unique_lock<std::mutex> lock(mempool_mutex);
    std::vector<Transaction> transactions;
    transactions.reserve(count);

    for (const auto& tx : transactionQueue) {
        transactions.push_back(tx);
        if (transactions.size() >= count) {
            break;
        }
    }

    return transactions;
}

bool MemPool::hasTransaction(const Transaction& transaction) const {
    std::unique_lock<std::mutex> lock(mempool_mutex);
    return transactionQueue.find(transaction) != transactionQueue.end();
}

size_t MemPool::size() const {
    std::unique_lock<std::mutex> lock(mempool_mutex);
    return transactionQueue.size();
}

std::pair<std::vector<char>, size_t> MemPool::getRaw() const {
    std::unique_lock<std::mutex> lock(mempool_mutex);
    size_t bufferSize = transactionQueue.size() * TRANSACTIONINFO_BUFFER_SIZE;
    std::vector<char> buffer(bufferSize);

    size_t offset = 0;
    for (const auto& tx : transactionQueue) {
        memcpy(buffer.data() + offset, tx.getRaw().data(), TRANSACTIONINFO_BUFFER_SIZE);
        offset += TRANSACTIONINFO_BUFFER_SIZE;
    }

    return std::make_pair(buffer, bufferSize);
}

void MemPool::finishBlock(Block& block) {
    std::unique_lock<std::mutex> lock(mempool_mutex);
    for (const auto& tx : block.getTransactions()) {
        auto it = transactionQueue.find(tx);
        if (it != transactionQueue.end()) {
            transactionQueue.erase(it);

            if (!tx.isFee()) {
                mempoolOutgoing[tx.fromWallet()] -= tx.getAmount() + tx.getFee();

                if (mempoolOutgoing[tx.fromWallet()] == 0) {
                    mempoolOutgoing.erase(tx.fromWallet());
                }
            }
        }
    }
}