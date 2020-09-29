//
// Created by Tyler on 10/9/20.
//

#ifndef NDNCERT_NDNCERT_DLEDGER_UTIL_HPP
#define NDNCERT_NDNCERT_DLEDGER_UTIL_HPP

#include <dledger/config.hpp>
#include <dledger/ledger.hpp>
#include <dledger/record.hpp>
#include <detail/ca-request-state.hpp>

namespace ndn {
namespace ndncert {

class DledgerUtil {
public:
static shared_ptr <dledger::Ledger>
getDledgerByConfig(std::string configPath, security::KeyChain &keychain, Face &face);

static bool
checkNdncertRecord(const Data& r);

static void
addRequestToLedger(shared_ptr<dledger::Ledger> dledger, const ca::RequestState& s);

};
}
}

#endif //NDNCERT_NDNCERT_DLEDGER_UTIL_HPP
