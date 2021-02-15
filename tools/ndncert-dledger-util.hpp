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
  static unique_ptr<DledgerUtil>
      getDledgerFromConfig(std::string configPath, security::KeyChain &keychain, Face &face);
  virtual void
  addRequestToLedger(const ca::RequestState &s) = 0;

};

class LoggingDledgerUtil: public DledgerUtil {
public:
  LoggingDledgerUtil(std::string configPath, security::KeyChain &keychain, Face &face);

  void
  addRequestToLedger(const ca::RequestState &s);
private:
  static bool
  checkNdncertRecord(const Data& r);

private:
  shared_ptr<dledger::Ledger> m_dledger;
};

class AnchorDledgerUtil: public DledgerUtil {
public:
  AnchorDledgerUtil(std::string configPath, security::KeyChain &keychain, Face &face);

  void
  addRequestToLedger(const ca::RequestState &s);
private:
  static bool
  checkNdncertRecord(const Data& r);

private:
  shared_ptr<dledger::Ledger> m_dledger;
};

} // namespace ndncert
} // namespace ndn

#endif //NDNCERT_NDNCERT_DLEDGER_UTIL_HPP
