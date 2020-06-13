// Copyright (c) 2018 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <bench/bench.h>
#include <blockfilter.h>

static void ConstructGCSFilter(benchmark::State& state)
{
    GCSFilter::ElementSet elements;
    for (int i = 0; i < 10000; ++i) {
        GCSFilter::Element element(32);
        element[0] = static_cast<unsigned char>(i);
        element[1] = static_cast<unsigned char>(i >> 8);
        elements.insert(std::move(element));
    }

    uint64_t siphash_k0 = 0;
    while (state.KeepRunning()) {
        GCSFilter filter({siphash_k0, 0, 20, 1 << 20}, elements);

        siphash_k0++;
    }
}

static void MatchGCSFilter(benchmark::State& state)
{
    GCSFilter::ElementSet elements;
    for (int i = 0; i < 10000; ++i) {
        GCSFilter::Element element(32);
        element[0] = static_cast<unsigned char>(i);
        element[1] = static_cast<unsigned char>(i >> 8);
        elements.insert(std::move(element));
    }
    GCSFilter filter({0, 0, 20, 1 << 20}, elements);

    while (state.KeepRunning()) {
        filter.Match(GCSFilter::Element());
    }
}

static void DecodeGCSFilter(benchmark::State& state)
{
    GCSFilter::ElementSet elements;
    for (int i = 0; i < 10000; ++i) {
        GCSFilter::Element element(32);
        element[0] = static_cast<unsigned char>(i);
        element[1] = static_cast<unsigned char>(i >> 8);
        elements.insert(std::move(element));
    }
    GCSFilter filter({0, 0, 20, 1 << 20}, elements);
    std::vector<unsigned char> encoded_filter = filter.GetEncoded();

    while (state.KeepRunning()) {
        GCSFilter filter({0, 0, 20, 1 << 20}, encoded_filter);
    }
}

BENCHMARK(ConstructGCSFilter, 1000);
BENCHMARK(DecodeGCSFilter, 25000);
BENCHMARK(MatchGCSFilter, 50 * 1000);
