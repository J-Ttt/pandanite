#pragma once

#include <set>
#include <map>
#include <thread>
#include <mutex>
#include <list>
#include <map>
#include <memory>
#include "../core/host_manager.hpp"
#include "../core/transaction.hpp"
#include "executor.hpp"
#include "../core/block.hpp"

class BlockChain;

class MemPool {
public:
    MemPool(HostManager& h, BlockChain& b);
    ~MemPool();
    void sync();
    ExecutionStatus addTransaction(const Transaction& transaction);
    void finishBlock(Block& block);
    bool hasTransaction(const Transaction& transaction) const;
    size_t size() const;
    std::pair<std::vector<char>, size_t> getRaw() const;
    std::vector<Transaction> getTransactions(size_t count) const;

protected:
    void mempool_sync();
    bool shutdown;
    std::mutex shutdownLock;
    std::map<PublicWalletAddress, TransactionAmount> mempoolOutgoing;
    std::list<Transaction> toSend;
    BlockChain& blockchain;
    HostManager& hosts;
    std::set<Transaction> transactionQueue;
    std::vector<std::thread> syncThread;
    mutable std::mutex mempool_mutex;
    std::mutex toSend_mutex;
};
