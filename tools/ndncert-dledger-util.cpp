//
// Created by Tyler on 10/9/20.
//

#include "ndncert-dledger-util.hpp"

#include <detail/ndncert-common.hpp>
#include <boost/property_tree/json_parser.hpp>
#include <iostream>
#include <detail/ca-request-state.hpp>


using namespace dledger;

namespace ndn{
namespace ndncert {

shared_ptr <dledger::Ledger>
DledgerUtil::getDledgerByConfig(std::string configPath, security::KeyChain &keychain, Face &face) {

  std::list <std::string> peerCertFiles;

  JsonSection json;
  boost::property_tree::json_parser::read_json(configPath, json);
  std::string peerPrefix = json.get("peerPrefix", "");
  std::string multicastPrefix = json.get("multicastPrefix", "");
  std::string anchorCertFile = json.get("anchorCert", "");
  std::string databasePath = json.get("databasePath", "/var/log/ndncert-dledger/");
  for (const auto &v: json.get_child("peerCert")) {
    assert(v.first.empty()); // array elements have no names
    peerCertFiles.push_back(v.second.data());
  }

  auto dledgerConfig = dledger::Config::CustomizedConfig(multicastPrefix, peerPrefix, anchorCertFile,
          databasePath, peerCertFiles);

  dledgerConfig->precedingRecordNum = json.get<int>("precedingRecordNum", dledgerConfig->precedingRecordNum);
  dledgerConfig->appendWeight = json.get<int>("appendWeight", dledgerConfig->appendWeight);
  dledgerConfig->contributionWeight = json.get<int>("contributionWeight", dledgerConfig->contributionWeight);
  dledgerConfig->confirmWeight = json.get<int>("confirmWeight", dledgerConfig->confirmWeight);

  dledgerConfig->recordProductionRateLimit = time::milliseconds(json.get<int>("rateLimit", 100));

  auto ledger = dledger::Ledger::initLedger(*dledgerConfig, keychain, face);
  if (!json.get("recordGraphLog", "").empty()) {
    auto dot_log = std::make_shared<std::ofstream>(std::ofstream());
    dot_log->open(json.get("recordGraphLog", ""));

    ledger->setOnRecordAppConfirmed([dot_log, &ledger](const Record &r) {
      std::string recordDigest = '"' + r.getProducerID() + '/' + r.getUniqueIdentifier() + '"';
      std::string attribute = r.getType() == dledger::CERTIFICATE_RECORD
              ? "[fillcolor=blue, style=filled, fontcolor=white]" : (
                      r.getType() == dledger::REVOCATION_RECORD
                      ? "[fillcolor=red, style=filled, fontcolor=white]" : "[]");
      *dot_log << recordDigest << " " << attribute << ";" << std::endl;
      for (const auto &ptr: r.getPointersFromHeader()) {
        auto ancestor = ledger->getRecord(ptr.toUri());
        if (ancestor.has_value())
          *dot_log << recordDigest << " -> " << '"' << ancestor->getProducerID() << '/' <<
          ancestor->getUniqueIdentifier() << '"' << ";" << std::endl;
      }

      if (r.getType() == dledger::CERTIFICATE_RECORD) {
        dledger::CertificateRecord certRecord(r);
        for (const auto &ptr: certRecord.getPrevCertificates()) {
          auto ancestor = ledger->getRecord(ptr.toUri());
          if (ancestor.has_value())
            *dot_log << recordDigest << " -> " << '"' << ancestor->getProducerID() << '/' <<
            ancestor->getUniqueIdentifier() << '"' << "[color=blue, style=dashed];"
            << std::endl;
        }
      }
    });
  }

  return ledger;
}

bool
DledgerUtil::checkNdncertRecord(const Data& r) {
    Record record = r;
    if (record.getType() == GENERIC_RECORD) {
    bool hasName = false;
    bool hasCert = false;
    for (const auto& item : record.getRecordItems()) {
    if (item.type() == ndn::tlv::Name) {
    if (hasName) return false;
    if (security::v2::Certificate::isValidName(Name(item))) {
    hasName = true;
} else {
    return false;
}
} else if (item.type() == ndn::tlv::Data) {
if (hasCert) return false;
try {
auto c = security::v2::Certificate(item);
hasCert = true;
} catch (std::exception& e) {
return false;
}
} else {
return false;
}
}
if (hasCert && hasName) return false;
if (!hasCert && !hasName) return false;
}
return true;
}

void
DledgerUtil::addRequestToLedger(shared_ptr<Ledger> dledger, const ca::RequestState& request) {
    //append / revoke record
    std::string identifier = (request.requestType == RequestType::REVOKE ?
                              std::string("Revoke_") : std::string("Cert_")) + readString(request.cert.getName().get(-1));
    Record record(RecordType::GENERIC_RECORD, identifier);
    if (request.requestType == RequestType::REVOKE) {
        record.addRecordItem(request.cert.getFullName().wireEncode());
    } else {
        record.addRecordItem(request.cert.wireEncode());
    }
    ReturnCode result = dledger->createRecord(record);
    if (!result.success()) {
        std::cout << "- Adding record error : " << result.what() << std::endl;
    }
}

}
}