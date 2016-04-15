// Copyright (c) 2016 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_BLOCK_ENCODINGS_H
#define BITCOIN_BLOCK_ENCODINGS_H

#include "primitives/block.h"

class CTxMemPool;

class TransactionCompressor {
private:
    CTransaction& tx;
public:
    TransactionCompressor(CTransaction& txIn) : tx(txIn) {}

    ADD_SERIALIZE_METHODS;

    template <typename Stream, typename Operation>
    inline void SerializationOp(Stream& s, Operation ser_action, int nType, int nVersion) {
        READWRITE(tx); //TODO: Compress tx encoding
    }
};

struct BlockTransactionsRequest {
    uint256 blockhash;
    std::vector<uint32_t> indexes;

    ADD_SERIALIZE_METHODS;

    template <typename Stream, typename Operation>
    inline void SerializationOp(Stream& s, Operation ser_action, int nType, int nVersion) {
        READWRITE(blockhash);
        uint64_t indexes_size = indexes.size();
        READWRITE(VARINT(indexes_size));
        if (ser_action.ForRead()) {
            size_t i = 0;
            while (indexes.size() < indexes_size) {
                indexes.resize(std::min(1000 + indexes.size(), indexes_size));
                for (; i < indexes.size(); i++)
                    READWRITE(VARINT(indexes[i]));
            }

            uint32_t offset = 0;
            for (size_t i = 0; i < indexes.size(); i++) {
                if (uint64_t(indexes[i]) + uint64_t(offset) > std::numeric_limits<uint32_t>::max())
                    throw std::ios_base::failure("indexes overflowed 32-bits");
                indexes[i] = indexes[i] + offset;
                offset = indexes[i] + 1;
            }
        } else {
            for (size_t i = 0; i < indexes.size(); i++) {
                uint32_t index = indexes[i] - (i == 0 ? 0 : (indexes[i - 1] + 1));
                READWRITE(VARINT(index));
            }
        }
    }
};

struct BlockTransactions {
    uint256 blockhash;
    std::vector<CTransaction> txn;

    BlockTransactions() {}
    BlockTransactions(const BlockTransactionsRequest& req) :
        blockhash(req.blockhash), txn(req.indexes.size()) {}

    ADD_SERIALIZE_METHODS;

    template <typename Stream, typename Operation>
    inline void SerializationOp(Stream& s, Operation ser_action, int nType, int nVersion) {
        READWRITE(blockhash);
        uint64_t txn_size = txn.size();
        READWRITE(VARINT(txn_size));
        if (ser_action.ForRead()) {
            size_t i = 0;
            while (txn.size() < txn_size) {
                txn.resize(std::min(1000 + txn.size(), txn_size));
                for (; i < txn.size(); i++)
                    READWRITE(REF(TransactionCompressor(txn[i])));
            }
        } else {
            for (size_t i = 0; i < txn.size(); i++)
                READWRITE(REF(TransactionCompressor(txn[i])));
        }
    }
};

struct PrefilledTransaction {
    // Used as an offset since last prefilled tx in CBlockHeaderAndShortTxIDs,
    // as a proper transaction-in-block-index in PartiallyDownloadedBlock
    uint16_t index;
    CTransaction tx;

    ADD_SERIALIZE_METHODS;

    template <typename Stream, typename Operation>
    inline void SerializationOp(Stream& s, Operation ser_action, int nType, int nVersion) {
        READWRITE(VARINT(index));
        READWRITE(REF(TransactionCompressor(tx)));
    }
};

typedef enum ReadStatus_t
{
    READ_STATUS_OK,
    READ_STATUS_INVALID, // Invalid object, peer is sending bogus crap
    READ_STATUS_FAILED, // Failed to process object
} ReadStatus;

class CBlockHeaderAndShortTxIDs {
private:
    mutable uint256 shorttxidhash;
    uint64_t nonce;

    void FillShortTxIDSelector() const;

    friend class PartiallyDownloadedBlock;
protected:
    std::vector<uint64_t> shorttxids;
    std::vector<PrefilledTransaction> prefilledtxn;

public:
    CBlockHeader header;

    // Dummy for deserialization
    CBlockHeaderAndShortTxIDs() {}

    CBlockHeaderAndShortTxIDs(const CBlock& block);

    uint64_t GetShortID(const uint256& txhash) const;

    uint32_t BlockTxCount() const { return shorttxids.size() + prefilledtxn.size(); }

    ADD_SERIALIZE_METHODS;

    template <typename Stream, typename Operation>
    inline void SerializationOp(Stream& s, Operation ser_action, int nType, int nVersion) {
        READWRITE(header);
        READWRITE(nonce);
        READWRITE(shorttxids);
        READWRITE(prefilledtxn);
        if (ser_action.ForRead())
            FillShortTxIDSelector();
    }
};

class PartiallyDownloadedBlock {
protected:
    std::vector<uint256> txhashes;
    std::vector<PrefilledTransaction> prefilledtxn;
    CTxMemPool* pool;
public:
    CBlockHeader header;
    PartiallyDownloadedBlock(CTxMemPool* poolIn) : pool(poolIn) {}
    ~PartiallyDownloadedBlock();

    ReadStatus InitData(const CBlockHeaderAndShortTxIDs& comprblock);
    bool IsTxAvailable(size_t index) const;
    ReadStatus FillBlock(CBlock& block, const std::vector<CTransaction>& vtx_missing) const;
};

#endif
