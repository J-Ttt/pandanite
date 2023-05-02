#include "../external/http.hpp"
#include <map>
#include <iostream>
#include <stdexcept>
#include <stdlib.h>
#include <map>
#include <algorithm>
#include <mutex>
#include <functional>
#include <thread>
#include <cstring>
#include <cmath>
#include <fstream>
#include <algorithm>
#include <future>
#include "../core/merkle_tree.hpp"
#include "../core/logger.hpp"
#include "../core/helpers.hpp"
#include "../core/api.hpp"
#include "../core/user.hpp"
#include "blockchain.hpp"
#include "mempool.hpp"
#include "genesis.hpp"

#define FORK_CHAIN_POP_COUNT 100
#define FORK_RESET_RETRIES 3
#define MAX_DISCONNECTS_BEFORE_RESET 10
#define FAILURES_BEFORE_POP_ATTEMPT 1

using namespace std;

void chain_sync(BlockChain& blockchain) {
    std::mutex sync_mutex;
    while (true) {
        std::this_thread::sleep_for(std::chrono::milliseconds(10000));
        if (blockchain.shutdown) break;
        if (!blockchain.isSyncing && blockchain.hosts.getBlockCount() > blockchain.numBlocks) {
            std::unique_lock<std::mutex> lock(sync_mutex, std::try_to_lock);
            if (!lock.owns_lock()) {
                continue;
            }

            std::vector<std::future<ExecutionStatus>> futures;
            unsigned int num_threads = std::thread::hardware_concurrency();
            std::atomic<uint64_t> current_block{blockchain.numBlocks + 1};
            uint64_t target_block = blockchain.hosts.getBlockCount();

            for (unsigned int i = 0; i < num_threads; ++i) {
                futures.push_back(std::async(std::launch::async, [&]() -> ExecutionStatus {
                    while (true) {
                        uint64_t block_id = current_block.fetch_add(1);
                        if (block_id > target_block) {
                            return SUCCESS;
                        }

                        ExecutionStatus status = blockchain.startChainSync();
                        if (status != SUCCESS) {
                            return status;
                        }
                    }
                }));
            }

            bool success = true;
            for (auto& future : futures) {
                ExecutionStatus status = future.get();
                if (status != SUCCESS) {
                    success = false;
                    break;
                }
            }

            if (!success) {
                blockchain.retries++;
                if (blockchain.retries > FORK_RESET_RETRIES) {
                    Logger::logError(RED + "[FATAL]" + RESET, "Max Rollback Tries Reached.");
                    blockchain.resetChain();
                    blockchain.recomputeLedger();
                } else {
                    Logger::logError(RED + "[ERROR]" + RESET, "Rollback retry #" + to_string(blockchain.retries));
                    for (uint64_t i = 0; i < FORK_CHAIN_POP_COUNT * blockchain.retries; i++) {
                        if (blockchain.numBlocks == 1) break;
                        blockchain.popBlock();
                    }
                    blockchain.recomputeLedger();
                }
            } else {
                Logger::logStatus("Chain Sync Status: SUCCESS Top Block: " + to_string(blockchain.numBlocks));
                blockchain.retries = 0;
            }

            lock.unlock();
        } else {
            Logger::logStatus("Debug isSyncing: " + to_string(blockchain.isSyncing));
            Logger::logStatus("Debug hosts.getBlockCount: " + to_string(blockchain.hosts.getBlockCount()));
            Logger::logStatus("Debug numBlocks: " + to_string(blockchain.numBlocks));
        }
    }
}

BlockChain::BlockChain(HostManager& hosts, string ledgerPath, string blockPath, string txdbPath) : hosts(hosts) {
    if (ledgerPath == "") ledgerPath = LEDGER_FILE_PATH;
    if (blockPath == "") blockPath = BLOCK_STORE_FILE_PATH;
    if (txdbPath == "") txdbPath = TXDB_FILE_PATH;
    this->memPool = nullptr;
    this->shutdown = false;
    this->retries = 0;
    this->ledger.init(ledgerPath);
    this->blockStore = std::make_unique<BlockStore>();
    this->blockStore->init(blockPath);
    this->txdb.init(txdbPath);
    hosts.setBlockstore(this->blockStore);
    this->initChain();
}

BlockChain::~BlockChain() {
    this->shutdown = true;
}

void BlockChain::initChain() {
    this->isSyncing = false;
    if (this->blockStore->hasBlockCount()) {
        Logger::logStatus("BlockStore exists, loading from disk");
        size_t count = this->blockStore->getBlockCount();
        this->numBlocks = count;
        this->targetBlockCount = count;
        Block lastBlock = this->blockStore->getBlock(count);
        this->totalWork = this->blockStore->getTotalWork();
        this->difficulty = lastBlock.getDifficulty();
        this->lastHash = lastBlock.getHash();
    } else {
        this->resetChain();
    }
}

void BlockChain::resetChain() {
    Logger::logStatus("BlockStore does not exist");
    this->difficulty = 16;
    this->targetBlockCount = 1;
    this->numBlocks = 0;
    this->totalWork = 0;
    this->lastHash = NULL_SHA256_HASH;

    // reset the ledger, block & tx stores
    this->ledger.clear();
    this->blockStore->clear();
    this->txdb.clear();

    json genesisJson;
    try {
         genesisJson = readJsonFromFile("genesis.json");
    } catch(...) {
        Logger::logError(RED + "[FATAL]" + RESET, "Could not load genesis.json file.");
        exit(-1);
    }
    Block genesis(genesisJson);

    ExecutionStatus status = this->addBlock(genesis);
    if (status != SUCCESS) {
        throw std::runtime_error("Could not load genesis block: " + executionStatusAsString(status));
    }
}

void BlockChain::closeDB() {
    txdb.closeDB();
    ledger.closeDB();
    this->blockStore->closeDB();
}

void BlockChain::deleteDB() {
    this->closeDB();
    txdb.deleteDB();
    ledger.deleteDB();
    this->blockStore->deleteDB();
}

std::pair<uint8_t*, size_t> BlockChain::getRaw(uint32_t blockId) const{
    if (blockId <= 0 || blockId > this->numBlocks) throw std::runtime_error("Invalid block");
    return this->blockStore->getRawData(blockId);
}

BlockHeader BlockChain::getBlockHeader(uint32_t blockId) const{
    if (blockId <= 0 || blockId > this->numBlocks) throw std::runtime_error("Invalid block");
    return this->blockStore->getBlockHeader(blockId);
}

void BlockChain::sync() {
    this->syncThread.push_back(std::thread(chain_sync, ref(*this)));
}

const Ledger& BlockChain::getLedger() const{
    return this->ledger;
}

Ledger& BlockChain::getLedger(){
    return ledger;
}

uint32_t BlockChain::getBlockCount() const {
    return this->numBlocks;
}

uint32_t BlockChain::getCurrentMiningFee(uint64_t blockId) const{
    uint64_t logicalBlock = blockId + 125180 + 7750 + 18000;
    double amount = 50.0;
    while (logicalBlock >= 666666) {
        amount *= (2.0/3.0);
        logicalBlock-= 666666;
    }
    return PDN(amount);
}
double BlockChain::getSupply() const {
  std::unique_lock<std::mutex> ul(lock);
  double supply = 0;
  double amount_offset=6647477.8490; // from previous fork
  double amount = 50.0;
  uint64_t blocks = numBlocks;
  while (blocks >= 666666) {
    supply += 666666 * amount;
    amount *= (2.0 / 3.0);
    blocks -= 666666;
  }
  supply += blocks * amount;
  return supply + amount_offset;
};

Bigint BlockChain::getTotalWork() const {
    return this->totalWork;
}

Block BlockChain::getBlock(uint32_t blockId) const {
    if (blockId <= 0 || blockId > this->numBlocks) throw std::runtime_error("Invalid block");
    return this->blockStore->getBlock(blockId);
}

ExecutionStatus BlockChain::verifyTransaction(const Transaction& t) {
    if (this->isSyncing) return IS_SYNCING;
    if (t.isFee()) return EXTRA_MINING_FEE;
    if (!t.signatureValid()) return INVALID_SIGNATURE;
    LedgerState deltas;
    // verify the transaction is consistent with ledger
    std::unique_lock<std::mutex> ul(lock);
    ExecutionStatus status = Executor::ExecuteTransaction(this->getLedger(), t, deltas);

    //roll back the ledger to it's original state:
    Executor::Rollback(this->getLedger(), deltas);

    if (this->txdb.hasTransaction(t)) {
        status = EXPIRED_TRANSACTION;
    }

    return status;
}

SHA256Hash BlockChain::getLastHash() const {
    return this->lastHash;
}

TransactionAmount BlockChain::getWalletValue(PublicWalletAddress addr) const{
    return this->getLedger().getWalletValue(addr);
}

uint32_t computeDifficulty(int32_t currentDifficulty, int32_t elapsedTime, int32_t expectedTime) {
    uint32_t newDifficulty = currentDifficulty;
    if (elapsedTime > expectedTime) {
        int k = 2;
        int lastK = 1;
        while(newDifficulty > MIN_DIFFICULTY) {
                if(abs(elapsedTime/k - expectedTime) > abs(elapsedTime/lastK - expectedTime) ) {
                    break;
                }
            newDifficulty--;
            lastK = k;
            k*=2;
        }
        return newDifficulty;
    } else {
        int k = 2;
        int lastK = 1;
        while(newDifficulty < 254) {
            if(abs(elapsedTime*k - expectedTime) > abs(elapsedTime*lastK - expectedTime) ) {
                break;
            }
            newDifficulty++;
            lastK = k;
            k*=2;
        }
        return newDifficulty;
    }
}

void BlockChain::updateDifficulty() {
    if (this->numBlocks <= DIFFICULTY_LOOKBACK*2) return;
    if (this->numBlocks % DIFFICULTY_LOOKBACK != 0) return;
    int firstID = this->numBlocks - DIFFICULTY_LOOKBACK;
    int lastID = this->numBlocks;  
    Block first = this->getBlock(firstID);
    Block last = this->getBlock(lastID);
    int32_t elapsed = last.getTimestamp() - first.getTimestamp(); 
    uint32_t numBlocksElapsed = lastID - firstID;
    int32_t target = numBlocksElapsed * DESIRED_BLOCK_TIME_SEC;
    int32_t difficulty = last.getDifficulty();
    this->difficulty = computeDifficulty(difficulty, elapsed, target);
    if (this->numBlocks >= PUFFERFISH_START_BLOCK && this->numBlocks < (PUFFERFISH_START_BLOCK + DIFFICULTY_LOOKBACK*2)) {
        this->difficulty = MIN_DIFFICULTY;
    }
}

uint32_t BlockChain::findBlockForTransactionId(SHA256Hash txid) {
    uint32_t blockId = this->txdb.blockForTransactionId(txid);
    return blockId;
}

uint32_t BlockChain::findBlockForTransaction(Transaction &t) {
    uint32_t blockId = this->txdb.blockForTransaction(t);
    return blockId;
}

void BlockChain::setMemPool(std::shared_ptr<MemPool> memPool) {
    this->memPool = memPool;
}

uint8_t BlockChain::getDifficulty() const{
    return this->difficulty;
}

vector<Transaction> BlockChain::getTransactionsForWallet(PublicWalletAddress addr) const{
    vector<SHA256Hash> txids = this->blockStore->getTransactionsForWallet(addr);
    vector<Transaction> ret;
    // TODO: this is pretty inefficient -- might want direct index of transactions
    for (auto txid : txids) {
        uint32_t blockId = this->txdb.blockForTransactionId(txid);
        if (blockId > 0)
        {
            Block b = this->blockStore->getBlock(blockId);
            for (auto tx : b.getTransactions()) {
                if (tx.hashContents() == txid) {
                    ret.push_back(tx);
                    break;
                }
            }
        }
    }
    return std::move(ret);
}

void BlockChain::popBlock() {
    Block last = this->getBlock(this->getBlockCount());
    Executor::RollbackBlock(last, this->ledger, this->txdb);
    this->numBlocks--;
    Bigint base = 2;
    this->totalWork -= base.pow((int)last.getDifficulty());
    this->blockStore->setTotalWork(this->totalWork);
    this->blockStore->setBlockCount(this->numBlocks);
    this->blockStore->removeBlockWalletTransactions(last);
    if (this->getBlockCount() > 1) {
        Block newLast = this->getBlock(this->getBlockCount());
        this->difficulty = newLast.getDifficulty();
        this->lastHash = newLast.getHash();
    } else {
        this->resetChain();
    }
}

ExecutionStatus BlockChain::addBlockSync(Block& block) {
    if (this->isSyncing) {
        return IS_SYNCING;
    } else {
        std::unique_lock<std::mutex> ul(lock);
        return this->addBlock(block);
    }
}
    

ExecutionStatus BlockChain::addBlock(Block& block) {
    // check difficulty + nonce
    if (block.getTransactions().size() > MAX_TRANSACTIONS_PER_BLOCK) return INVALID_TRANSACTION_COUNT;
    if (block.getId() != this->numBlocks + 1) return INVALID_BLOCK_ID;
    if (block.getDifficulty() != this->difficulty) return INVALID_DIFFICULTY;
    if (!block.verifyNonce()) return INVALID_NONCE;
    if (block.getLastBlockHash() != this->getLastHash()) return INVALID_LASTBLOCK_HASH;
    if (block.getId() != 1) {
        // block must be less than 2 hrs into future from network time
        uint64_t maxTime = this->hosts.getNetworkTimestamp() + 120*60;
        if (block.getTimestamp() > maxTime) return BLOCK_TIMESTAMP_IN_FUTURE;

        // block must be after the median timestamp of last 10 blocks
        if (this->numBlocks > 10) {
            vector<uint64_t> times;
            for(int i = 0; i < 10; i++) {
                Block b = this->getBlock(this->numBlocks - i);
                times.push_back(b.getTimestamp());
            }
            std::sort(times.begin(), times.end());
            // compute median
            uint64_t medianTime;
            if (times.size() % 2 == 0) {
                medianTime = (times[times.size()/2] + times[times.size()/2 - 1])/2;
            } else {
                medianTime = times[times.size()/2];
            }
            if (block.getTimestamp() < medianTime) return BLOCK_TIMESTAMP_TOO_OLD;
        }
    }
    // compute merkle tree and verify root matches;
    MerkleTree m;
    m.setItems(block.getTransactions());
    SHA256Hash computedRoot = m.getRootHash();
    if (block.getMerkleRoot() != computedRoot) return INVALID_MERKLE_ROOT;
    LedgerState deltasFromBlock;
    ExecutionStatus status = Executor::ExecuteBlock(block, this->ledger, this->txdb, deltasFromBlock, this->getCurrentMiningFee(block.getId()));

    if (status != SUCCESS) {
        Executor::Rollback(this->ledger, deltasFromBlock);
    } else {
        if (this->memPool != nullptr) {
            this->memPool->finishBlock(block);
        }
        // add all transactions to txdb:
        for(auto t : block.getTransactions()) {
            this->txdb.insertTransaction(t, block.getId());
        }
        this->blockStore->setBlock(block);
        this->numBlocks++;
        this->totalWork = addWork(this->totalWork, block.getDifficulty());
        this->blockStore->setTotalWork(this->totalWork);
        this->blockStore->setBlockCount(this->numBlocks);
        this->lastHash = block.getHash();
        this->updateDifficulty();
        Logger::logStatus("Added block " + to_string(block.getId()));
        Logger::logStatus("difficulty= " + to_string(block.getDifficulty()));
    }
    return status;
}

map<string, uint64_t> BlockChain::getHeaderChainStats() const{
    return this->hosts.getHeaderChainStats();
}

void BlockChain::recomputeLedger() {
    this->ledger.clear();
    this->txdb.clear();
    for(int i = 1; i <= this->numBlocks; i++) {
        Logger::logStatus("Recompute: " + to_string(i));
        LedgerState deltas;
        Block block = this->getBlock(i);
        ExecutionStatus addResult = Executor::ExecuteBlock(block, this->ledger, this->txdb, deltas, this->getCurrentMiningFee(i));
        // add all transactions to txdb:
        for(auto t : block.getTransactions()) {
            if (!t.isFee()) this->txdb.insertTransaction(t, block.getId());
        }
        if (addResult != SUCCESS) {
            Logger::logError(RED + "[FATAL]" + RESET, "Corrupt blockchain. Exiting. Please delete data dir and sync from scratch.");
            exit(-1);
        }
    }
}

ExecutionStatus BlockChain::startChainSync() {
    std::unique_lock<std::mutex> ul(lock);
    this->isSyncing = true;
    string bestHost = this->hosts.getGoodHost();
    this->targetBlockCount = this->hosts.getBlockCount();
    // If our current chain is lower POW than the trusted host
    // remove anything that does not align with the hashes of the trusted chain
    if (this->hosts.getTotalWork() > this->getTotalWork()) {
        // iterate through our current chain until a hash diverges from trusted chain
        uint64_t toPop = 0;
        for(uint64_t i = 1; i <= this->numBlocks; i++) {
            SHA256Hash trustedHash = this->hosts.getBlockHash(bestHost, i);
            SHA256Hash myHash = this->getBlock(i).getHash();
            if (trustedHash != myHash) {
                toPop = this->numBlocks - i + FORK_CHAIN_POP_COUNT;
                break;
            }
        }
        // pop all subsequent blocks
        for (uint64_t i = 0; i < toPop; i++) {
            if (this->numBlocks == 1) break;
            this->popBlock();
        }
    }

    int startCount = this->numBlocks;

    int needed = this->targetBlockCount - startCount;
    if (needed > 0) Logger::logStatus("fetching target blockcount=" + to_string(this->targetBlockCount));
    // download any remaining blocks in batches
    uint64_t start = std::time(0);
    for(int i = startCount + 1; i <= this->targetBlockCount; i+=BLOCKS_PER_FETCH) {
        try {
            int end = min(this->targetBlockCount, i + BLOCKS_PER_FETCH - 1);
            bool failure = false;
            ExecutionStatus status;
            BlockChain &bc = *this;
            int count = 0;
            vector<Block> blocks;
            readRawBlocks(bestHost, i, end, blocks);
            for(auto & b : blocks) {   
                ExecutionStatus addResult = bc.addBlock(b);
                if (addResult != SUCCESS) {
                failure = true;
                status = addResult;
                Logger::logError("Chain failed at blockID, recomputing ledger", std::to_string(b.getId()));
                this->recomputeLedger();
                break;
                }
            }
            if (failure) {
                Logger::logError("BlockChain::startChainSync", executionStatusAsString(status));
                this->isSyncing = false;
                return status;
            }
        } catch (const std::exception &e) {
            this->isSyncing = false;
            Logger::logError("BlockChain::startChainSync", "Failed to load block" + string(e.what()));
            return UNKNOWN_ERROR;
        }
    }
    uint64_t final = std::time(0);
    uint64_t d = final - start;
    stringstream s;
    s<<"Downloaded " << needed <<" blocks in " << d << " seconds from " + bestHost;
    if (needed > 1) Logger::logStatus(s.str());
    this->isSyncing = false;
    return SUCCESS;
}
