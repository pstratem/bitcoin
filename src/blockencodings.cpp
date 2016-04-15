// Copyright (c) 2016 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "blockencodings.h"
#include "consensus/consensus.h"
#include "hash.h"
#include "random.h"
#include "streams.h"
#include "txmempool.h"


#define MIN_TRANSACTION_SIZE 60

CBlockHeaderAndShortTxIDs::CBlockHeaderAndShortTxIDs(const CBlock& block) :
        nonce(GetRand(std::numeric_limits<uint64_t>::max())),
        shorttxids(block.vtx.size() - 1), prefilledtxn(1), header(block) {
    FillShortTxIDSelector();
    prefilledtxn[0] = {0, block.vtx[0]};
    for (size_t i = 1; i < block.vtx.size(); i++) {
        const CTransaction& tx = block.vtx[i];
        shorttxids[i - 1] = GetShortID(tx.GetHash());
    }
}

void CBlockHeaderAndShortTxIDs::FillShortTxIDSelector() const {
    CDataStream stream(SER_NETWORK, PROTOCOL_VERSION);
    stream << header;
    CSHA256 hasher;
    hasher.Write((unsigned char*)&(*stream.begin()), stream.end() - stream.begin());
    hasher.Write((unsigned char*)&nonce, sizeof(nonce));
    hasher.Finalize(shorttxidhash.begin());
}

uint64_t CBlockHeaderAndShortTxIDs::GetShortID(const uint256& txhash) const {
    uint64_t res = 0, tmp = 0;
    const unsigned char *txhashit = txhash.begin(), *shorttxidsit = shorttxidhash.begin();
    for (uint8_t i = 0; i < 4; i++) {
        tmp = 0;
        for (uint8_t j = 0; j < sizeof(res); j++) {
            tmp |= (*txhashit ^ *shorttxidsit) << (j * 8);
            txhashit++; shorttxidsit++;
        }
        res += tmp;
    }
    return res;
}



ReadStatus PartiallyDownloadedBlock::InitData(const CBlockHeaderAndShortTxIDs& comprblock) {
    if (comprblock.header.IsNull() || (comprblock.shorttxids.empty() && comprblock.prefilledtxn.empty()))
        return READ_STATUS_INVALID;
    if (comprblock.shorttxids.size() + comprblock.prefilledtxn.size() > MAX_BLOCK_SIZE / MIN_TRANSACTION_SIZE)
        return READ_STATUS_INVALID;

    assert(header.IsNull() && txhashes.empty());
    header = comprblock.header;
    txhashes.resize(comprblock.shorttxids.size() + comprblock.prefilledtxn.size());

    prefilledtxn.reserve(comprblock.prefilledtxn.size());
    int32_t lastprefilledindex = -1;
    for (size_t i = 0; i < comprblock.prefilledtxn.size(); i++) {
        if (comprblock.prefilledtxn[i].tx.IsNull())
            return READ_STATUS_INVALID;

        lastprefilledindex += comprblock.prefilledtxn[i].index + 1;
        if (lastprefilledindex > std::numeric_limits<uint16_t>::max())
            return READ_STATUS_INVALID;
        if ((uint32_t)lastprefilledindex > comprblock.shorttxids.size() + i + 1) {
            // If we are inserting a tx at an index greater than our full list of shorttxids
            // plus the number of prefilled txn we've inserted, then we have txn for which we
            // have neither a prefilled txn or a shorttxid!
            return READ_STATUS_INVALID;
        }
        txhashes[lastprefilledindex] = comprblock.prefilledtxn[i].tx.GetHash();
        prefilledtxn.push_back({(uint16_t)lastprefilledindex, comprblock.prefilledtxn[i].tx});
    }

    // Calculate map of txids -> positions and check mempool to see what we have (or dont)
    std::map<uint64_t, uint16_t> shorttxids;
    uint16_t index_offset = 0;
    std::vector<PrefilledTransaction>::const_iterator prefilledit = prefilledtxn.begin();
    for (size_t i = 0; i < comprblock.shorttxids.size(); i++) {
        while (prefilledit != prefilledtxn.end() && i + index_offset == prefilledit->index) {
            index_offset++;
            prefilledit++;
        }
        shorttxids[comprblock.shorttxids[i]] = i + index_offset;
    }
    if (shorttxids.size() != comprblock.shorttxids.size())
        return READ_STATUS_FAILED; // Short ID collision

    LOCK(pool->cs);
    for (CTxMemPool::txiter it = pool->mapTx.begin(); it != pool->mapTx.end(); it++) {
        std::map<uint64_t, uint16_t>::iterator idit = shorttxids.find(comprblock.GetShortID(it->GetTx().GetHash()));
        if (idit != shorttxids.end()) {
            it->AddRef();
            txhashes[idit->second] = it->GetTx().GetHash();
            shorttxids.erase(idit);
        }
    }

    return READ_STATUS_OK;
}

bool PartiallyDownloadedBlock::IsTxAvailable(size_t index) const {
    assert(!header.IsNull());
    assert(index < txhashes.size());
    return !txhashes[index].IsNull();
}

ReadStatus PartiallyDownloadedBlock::FillBlock(CBlock& block, const std::vector<CTransaction>& vtx_missing) const {
    assert(!header.IsNull());
    block = header;
    block.vtx.resize(txhashes.size());

    size_t tx_missing_offset = 0;
    std::vector<PrefilledTransaction>::const_iterator prefilledit = prefilledtxn.begin();
    for (size_t i = 0; i < txhashes.size(); i++) {
        if (txhashes[i].IsNull()) {
            if (vtx_missing.size() <= tx_missing_offset)
                return READ_STATUS_INVALID;
            block.vtx[i] = vtx_missing[tx_missing_offset++];
        } else {
            if (prefilledit != prefilledtxn.end() && prefilledit->index == i) {
                block.vtx[i] = prefilledit->tx;
                prefilledit++;
            } else
                assert(pool->lookup(txhashes[i], block.vtx[i], true));
        }
    }
    assert(prefilledit == prefilledtxn.end());
    return vtx_missing.size() == tx_missing_offset ? READ_STATUS_OK : READ_STATUS_INVALID;
}

PartiallyDownloadedBlock::~PartiallyDownloadedBlock() {
    if (!header.IsNull()) {
        std::vector<PrefilledTransaction>::const_iterator prefilledit = prefilledtxn.begin();
        for (size_t i = 0; i < txhashes.size(); i++) {
            if (!txhashes[i].IsNull()) {
                if (prefilledit != prefilledtxn.end() && prefilledit->index == i)
                    prefilledit++;
                else
                    pool->ReleaseTxLock(txhashes[i]);
            }
        }
    }
}
