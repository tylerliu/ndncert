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

unique_ptr<DledgerUtil>
DledgerUtil::getDledgerFromConfig(std::string configPath, security::KeyChain &keychain, Face &face) {
  JsonSection json;
  boost::property_tree::json_parser::read_json(configPath, json);
  std::string type = json.get("type", "Logging");
  if (type == "logging") {
    return make_unique<LoggingDledgerUtil>(configPath, keychain, face);
  } else if (type == "anchor") {
    return make_unique<AnchorDledgerUtil>(configPath, keychain, face);
  } else {
    return nullptr;
  }
}

LoggingDledgerUtil::LoggingDledgerUtil(std::string configPath, security::KeyChain &keychain, Face &face) {

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

  m_dledger = dledger::Ledger::initLedger(*dledgerConfig, keychain, face);
  if (!json.get("recordGraphLog", "").empty()) {
    auto dot_log = std::make_shared<std::ofstream>(std::ofstream());
    dot_log->open(json.get("recordGraphLog", ""));

    m_dledger->setOnRecordAppConfirmed([dot_log, this](const Record &r) {
      std::string recordDigest = '"' + readString(r.getProducerPrefix().get(-1)) + '/' + r.getUniqueIdentifier() + '"';
      std::string attribute;
      attribute += r.getType() == dledger::CERTIFICATE_RECORD
              ? "[fillcolor=blue, style=filled, fontcolor=white]" : "";
      attribute += r.getType() == dledger::REVOCATION_RECORD
                      ? "[fillcolor=red, style=filled, fontcolor=white]" : "";
      attribute += r.getProducerPrefix() == Name("/dledger/test-e")
                   ? "[fillcolor=green, style=filled]" : "";
      *dot_log << recordDigest << " " << attribute << ";" << std::endl;
      for (const auto &ptr: r.getPointersFromHeader()) {
        auto ancestor = m_dledger->getRecord(ptr.toUri());
        if (ancestor.has_value())
          *dot_log << recordDigest << " -> " << '"' << ancestor->getProducerPrefix().get(-1) << '/' <<
          ancestor->getUniqueIdentifier() << '"' << ";" << std::endl;
      }

      if (r.getType() == dledger::CERTIFICATE_RECORD) {
        dledger::CertificateRecord certRecord(r);
        for (const auto &ptr: certRecord.getPrevCertificates()) {
          auto ancestor = m_dledger->getRecord(ptr.toUri());
          if (ancestor.has_value())
            *dot_log << recordDigest << " -> " << '"' << ancestor->getProducerPrefix().get(-1) << '/' <<
            ancestor->getUniqueIdentifier() << '"' << "[color=blue, style=dashed];"
            << std::endl;
        }
      }
    });
  }

  m_dledger->setOnRecordAppCheck(LoggingDledgerUtil::checkNdncertRecord);
}

bool
LoggingDledgerUtil::checkNdncertRecord(const Data& r) {
  Record record = r;
  if (record.getType() == GENERIC_RECORD) {
    bool hasName = false;
    bool hasCert = false;
    for (const auto &item : record.getRecordItems()) {
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
        } catch (std::exception &e) {
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
LoggingDledgerUtil::addRequestToLedger(const ca::RequestState& request) {
    //append / revoke record
    std::string identifier = (request.requestType == RequestType::REVOKE ?
                              std::string("Revoke_") : std::string("Cert_")) + readString(request.cert.getName().get(-1));
    Record record(RecordType::GENERIC_RECORD, identifier);
    if (request.requestType == RequestType::REVOKE) {
        record.addRecordItem(request.cert.getFullName().wireEncode());
    } else {
        record.addRecordItem(request.cert.wireEncode());
    }
    ReturnCode result = m_dledger->createRecord(record);
    if (!result.success()) {
        std::cout << "- Adding record error : " << result.what() << std::endl;
    }
}

AnchorDledgerUtil::AnchorDledgerUtil(std::string configPath, security::KeyChain &keychain, Face &face) {

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

  m_dledger = dledger::Ledger::initLedger(*dledgerConfig, keychain, face);
  if (!json.get("recordGraphLog", "").empty()) {
    auto dot_log = std::make_shared<std::ofstream>(std::ofstream());
    dot_log->open(json.get("recordGraphLog", ""));

    m_dledger->setOnRecordAppConfirmed([dot_log, this](const Record &r) {
      std::string recordDigest = '"' + readString(r.getProducerPrefix().get(-1)) + '/' +
          recordTypeToString(r.getType()).substr(0, 3) + '/' + r.getUniqueIdentifier() + '"';
      std::string attribute;
      attribute += r.getType() == dledger::CERTIFICATE_RECORD
                   ? "[fillcolor=blue, style=filled, fontcolor=white]" : "";
      attribute += r.getType() == dledger::REVOCATION_RECORD
                   ? "[fillcolor=red, style=filled, fontcolor=white]" : "";
      attribute += r.getProducerPrefix() == Name("/dledger/test-e")
                   ? "[fillcolor=green, style=filled]" : "";
      *dot_log << recordDigest << " " << attribute << ";" << std::endl;
      for (const auto &ptr: r.getPointersFromHeader()) {
        auto ancestor = m_dledger->getRecord(ptr.toUri());
        if (ancestor.has_value())
          *dot_log << recordDigest << " -> " << '"' << ancestor->getProducerPrefix().get(-1) << '/' <<
          recordTypeToString(ancestor->getType()).substr(0, 3) << '/' << ancestor->getUniqueIdentifier() << '"' << ";" << std::endl;
      }

      if (r.getType() == dledger::CERTIFICATE_RECORD) {
        dledger::CertificateRecord certRecord(r);
        for (const auto &ptr: certRecord.getPrevCertificates()) {
          auto ancestor = m_dledger->getRecord(ptr.toUri());
          if (ancestor.has_value())
            *dot_log << recordDigest << " -> " << '"' << ancestor->getProducerPrefix().get(-1) << '/' <<
                     ancestor->getUniqueIdentifier() << '"' << "[color=blue, style=dashed];"
                     << std::endl;
        }
      }
      dot_log->flush();
    });
  }

  m_dledger->setOnRecordAppCheck(AnchorDledgerUtil::checkNdncertRecord);
}

bool
AnchorDledgerUtil::checkNdncertRecord(const Data& r) {
  Record record = r;
  try {
    if (record.getType() == CERTIFICATE_RECORD) {
      CertificateRecord a(record);
    } else if (record.getType() == CERTIFICATE_RECORD) {
      RevocationRecord a(record);
    }
  } catch (std::exception e) {
    return false;
  }
  return true;
}

void
AnchorDledgerUtil::addRequestToLedger(const ca::RequestState& request) {
  //append / revoke record
  std::string identifier = readString(request.cert.getName().get(-1));
  ReturnCode result("uninitialized");
  if (request.requestType == RequestType::REVOKE) {
    RevocationRecord record(identifier);
    record.addCertificateNameItem(request.cert.getFullName());
    result = m_dledger->createRecord(record);
  } else {
    CertificateRecord record(identifier);
    record.addCertificateItem(request.cert);
    result = m_dledger->createRecord(record);
  }
  if (!result.success()) {
    std::cout << "- Adding record error : " << result.what() << std::endl;
  }
}

}
}