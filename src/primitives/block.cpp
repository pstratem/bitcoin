// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2019 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <logging.h>
#include <primitives/block.h>

#include <hash.h>
#include <tinyformat.h>

#include <execinfo.h>

void print_trace()
{
    void *array[64];
    char **strings;
    int size, i;

    size = backtrace(array, 64);
    strings = backtrace_symbols(array, size);
    if (strings != NULL)
    {
        LogInfo("Obtained %d stack frames.\n", size);
        for (i = 0; i < size; i++)
            LogInfo("%s\n", strings[i]);
    }

    free(strings);
}

uint256 CBlockHeader::GetHash() const
{
    uint256 hash = (HashWriter{} << *this).GetHash();
    void *array[64];
    int size{0};
    size = backtrace(array, 64);
    std::vector<void*> bt(array, array+size);
    hash_counter[hash][bt]++;
    if (hash_counter[hash][bt] > 10)
    {
        LogInfo("BIG %s %u\n", hash.ToString(), hash_counter[hash][bt]);
        print_trace();
    }
    return hash;
}

std::string CBlock::ToString() const
{
    std::stringstream s;
    s << strprintf("CBlock(hash=%s, ver=0x%08x, hashPrevBlock=%s, hashMerkleRoot=%s, nTime=%u, nBits=%08x, nNonce=%u, vtx=%u)\n",
        GetHash().ToString(),
        nVersion,
        hashPrevBlock.ToString(),
        hashMerkleRoot.ToString(),
        nTime, nBits, nNonce,
        vtx.size());
    for (const auto& tx : vtx) {
        s << "  " << tx->ToString() << "\n";
    }
    return s.str();
}
