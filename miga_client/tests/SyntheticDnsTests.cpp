#include "runtime/SyntheticDnsStore.h"
#include "runtime/SyntheticDnsWire.h"

#include <cassert>
#include <iterator>

using namespace miga::runtime;

namespace {
void WireQueries() {
    const auto query = BuildSyntheticDnsQuery("WiRe.Example", 1, 0x4321);
    const auto question = ParseSyntheticDnsQuestion(query);
    assert(question && question->name == "WiRe.Example" && question->type == 1 && question->id == 0x4321);
    for (size_t size = 0; size < query.size(); ++size)
        assert(!ParseSyntheticDnsQuestion(std::span(query).first(size)));

    auto malformed = query;
    malformed[12] = 0xc0;
    malformed[13] = 12;
    assert(!ParseSyntheticDnsQuestion(malformed));
    malformed = query;
    malformed[14] = '.';
    assert(!ParseSyntheticDnsQuestion(malformed));
    malformed = query;
    malformed.back() = 3;
    assert(!ParseSyntheticDnsQuestion(malformed));

    auto edns = query;
    edns[11] = 1;
    edns.insert(edns.end(), {0, 0, 41, 4, 208, 0, 0, 128, 0, 0, 4, 0, 12, 0, 0});
    const auto dnssec = ParseSyntheticDnsQuestion(edns);
    assert(dnssec && dnssec->requiresPassthrough);
    edns[query.size() + 7] = 0;
    const auto padded = ParseSyntheticDnsQuestion(edns);
    assert(padded && !padded->requiresPassthrough);
    const auto upstream = BuildSyntheticDnsQuery("WiRe.Example", 1, 0x4321, 1232);
    assert(upstream.size() == query.size() + 11 && upstream[11] == 1);
    assert(upstream[query.size() + 3] == 0x04 && upstream[query.size() + 4] == 0xd0);
    const auto parsedUpstream = ParseSyntheticDnsQuestion(upstream);
    assert(parsedUpstream && !parsedUpstream->requiresPassthrough && parsedUpstream->name == question->name);
    edns.back() = 1;
    assert(!ParseSyntheticDnsQuestion(edns));
    assert(BuildSyntheticDnsQuery(std::string(64, 'a') + ".example", 1, 1).empty());
    assert(NormalizeSyntheticDnsName("WiRe.Example") == "wire.example");
}

void WireAnswers() {
    const auto query = BuildSyntheticDnsQuery("example.com", 1, 0x4321);
    const auto question = ParseSyntheticDnsQuestion(query);
    assert(question);
    const auto answer = BuildSyntheticDnsAnswer(*question, 0xc612fffe);
    const std::vector<uint8_t> record{0xc0, 0x0c, 0, 1, 0, 1, 0, 0, 0, 60, 0, 4, 198, 18, 255, 254};
    assert(answer.size() == query.size() + record.size() && answer[0] == 0x43 && answer[1] == 0x21);
    assert(answer[2] == 0x81 && answer[3] == 0x80 && answer[7] == 1);
    assert(std::equal(record.begin(), record.end(), answer.begin() + static_cast<std::ptrdiff_t>(query.size())));
    assert(!ParseSyntheticDnsQuestion(answer));
    const auto associated = ReadSyntheticDnsResponse(answer);
    assert(associated && associated->name == "example.com" && associated->addresses.size() == 1);
    assert(associated->addresses.front() == std::make_pair(uint32_t(0xc612fffe), uint32_t(60)));
    const auto error = BuildSyntheticDnsAnswer(*question, 0xc612fffe, 2);
    assert(error.size() == query.size() && error[3] == 0x82 && error[7] == 0);

    const auto ipv6 = ParseSyntheticDnsQuestion(BuildSyntheticDnsQuery("example.com", 28, 7));
    assert(ipv6);
    const auto empty = BuildSyntheticDnsAnswer(*ipv6, std::nullopt);
    assert(empty.size() == query.size() && empty[3] == 0x80 && empty[7] == 0);
}

void AliasAnswers() {
    constexpr uint16_t typeA = 1;
    const auto query = BuildSyntheticDnsQuery("A.example", typeA, 42);
    const auto question = ParseSyntheticDnsQuestion(query);
    assert(question);
    auto reply = BuildSyntheticDnsAnswer(*question, std::nullopt);
    reply[7] = 3;
    reply.insert(reply.end(), {1, 'X', 0xc0, 0x0e, 0, 1, 0, 1, 0, 0, 0, 200, 0, 4, 1, 2, 3, 4});
    reply.insert(reply.end(), {1, 'B', 0xc0, 0x0e, 0, 1, 0, 1, 0, 0, 0, 30, 0, 4, 5, 6, 7, 8});
    reply.insert(reply.end(), {0xc0, 0x0c, 0, 5, 0, 1, 0, 0, 0, 20, 0, 4, 1, 'b', 0xc0, 0x0e});
    const auto parsed = ReadSyntheticDnsResponse(reply);
    assert(parsed && parsed->name == "a.example" && parsed->addresses.size() == 1);
    assert(parsed->addresses.front() == std::make_pair(uint32_t(0x05060708), uint32_t(20)));
    const auto other = ParseSyntheticDnsQuestion(BuildSyntheticDnsQuery("a.Example", typeA, 43));
    assert(other && RewriteSyntheticDnsResponseQuestion(reply, *other));
    assert(reply[1] == 43 && reply[13] == 'a' && reply[15] == 'E');
    assert(ReadSyntheticDnsResponse(reply)->addresses == parsed->addresses);
    reply[reply.size() - 3] = 'a';
    assert(!ReadSyntheticDnsResponse(reply));
    reply.pop_back();
    assert(!ReadSyntheticDnsResponse(reply));
}

void Store() {
    SyntheticDnsStore store;
    const auto first = store.FindOrAllocate("Example.COM");
    assert(first && SyntheticDnsStore::Contains(*first));
    assert(store.FindOrAllocate("example.com") == first);
    const auto second = store.FindOrAllocate("next.example");
    assert(second && second != first && store.LastAllocated() >= *second && store.LastAllocated() >= *first);
    assert(store.Lookup(*first) && *store.Lookup(*first) == "example.com");
    assert(!store.FindOrAllocate("invalid..example"));
    store.Clear();
    assert(!store.Lookup(*first) && !store.LastAllocated());
}

void NegativeTtl() {
    const auto question = *ParseSyntheticDnsQuestion(BuildSyntheticDnsQuery("example.com", 1, 42));
    auto reply = BuildSyntheticDnsAnswer(question, {}, 3);
    assert(ReadSyntheticDnsResponse(reply)->negativeTtl == 0);
    reply[9] = 1;
    const uint8_t soa[] = {0xc0, 0x0c, 0, 6, 0, 1, 0, 0, 0, 90, 0, 24,
        0xc0, 0x0c, 0xc0, 0x0c,
        0, 0, 0, 1, 0, 0, 0, 2, 0, 0, 0, 3, 0, 0, 0, 4, 0, 0, 0, 30};
    reply.insert(reply.end(), std::begin(soa), std::end(soa));
    const auto negative = ReadSyntheticDnsResponse(reply);
    assert(negative && negative->responseCode == 3 && negative->negativeTtl == 30);
    reply[3] &= 0xf0;
    const auto noData = ReadSyntheticDnsResponse(reply);
    assert(noData && noData->responseCode == 0 && noData->addresses.empty() && noData->negativeTtl == 30);
    const auto positive = ReadSyntheticDnsResponse(BuildSyntheticDnsAnswer(question, 0xc6120001u, 0, 70000));
    assert(positive && positive->addresses[0].second == 70000);
    reply.pop_back();
    assert(!ReadSyntheticDnsResponse(reply));
}

}

int main() {
    WireQueries();
    WireAnswers();
    AliasAnswers();
    Store();
    NegativeTtl();
}
