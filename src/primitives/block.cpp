// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2019 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <primitives/block.h>

#include <hash.h>
#include <tinyformat.h>

CBlockHeader::CBlockHeader(const ImmutableBlockHeader &header) :
    nVersion(header.nVersion),
    hashPrevBlock(header.hashPrevBlock),
    hashMerkleRoot(header.hashMerkleRoot),
    nTime(header.nTime),
    nBits(header.nBits),
    nNonce(header.nNonce)
{}

uint256 CBlockHeader::GetHash() const
{
    return (HashWriter{} << *this).GetHash();
}

CBlock::CBlock(const ImmutableBlock &block) :
    CBlockHeader(block),
    vtx(block.vtx)
{}

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

ImmutableBlockHeader::ImmutableBlockHeader(const CBlockHeader& header) :
    nVersion(header.nVersion),
    hashPrevBlock(header.hashPrevBlock),
    hashMerkleRoot(header.hashMerkleRoot),
    nTime(header.nTime),
    nBits(header.nBits),
    nNonce(header.nNonce)
{}

ImmutableBlock::ImmutableBlock(const CBlock& block) :
    ImmutableBlockHeader(block),
    vtx(block.vtx)
{
}

std::string ImmutableBlock::ToString() const
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
