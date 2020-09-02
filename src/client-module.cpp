/* -*- Mode:C++; c-file-style:"gnu"; indent-tabs-mode:nil; -*- */
/**
 * Copyright (c) 2017-2020, Regents of the University of California.
 *
 * This file is part of ndncert, a certificate management system based on NDN.
 *
 * ndncert is free software: you can redistribute it and/or modify it under the terms
 * of the GNU General Public License as published by the Free Software Foundation, either
 * version 3 of the License, or (at your option) any later version.
 *
 * ndncert is distributed in the hope that it will be useful, but WITHOUT ANY
 * WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A
 * PARTICULAR PURPOSE.  See the GNU General Public License for more details.
 *
 * You should have received copies of the GNU General Public License along with
 * ndncert, e.g., in COPYING.md file.  If not, see <http://www.gnu.org/licenses/>.
 *
 * See AUTHORS.md for complete list of ndncert authors and contributors.
 */

#include "client-module.hpp"
#include "logging.hpp"
#include "challenge-module.hpp"
#include "crypto-support/enc-tlv.hpp"
#include <ndn-cxx/util/io.hpp>
#include <ndn-cxx/security/signing-helpers.hpp>
#include <ndn-cxx/security/verification-helpers.hpp>
#include <ndn-cxx/util/random.hpp>
#include <ndn-cxx/security/transform/base64-encode.hpp>
#include <ndn-cxx/security/transform/buffer-source.hpp>
#include <ndn-cxx/security/transform/stream-sink.hpp>

namespace ndn {
namespace ndncert {

_LOG_INIT(ndncert.client);

ClientModule::ClientModule(security::v2::KeyChain& keyChain)
  : m_keyChain(keyChain)
{
}

ClientModule::~ClientModule()
{
  endSession();
}

shared_ptr<Interest>
ClientModule::generateProbeInfoInterest(const Name& caName)
{
  Name interestName = caName;
  if (readString(caName.at(-1)) != "CA")
    interestName.append("CA");
  interestName.append("_PROBE").append("INFO");
  auto interest = make_shared<Interest>(interestName);
  interest->setMustBeFresh(true);
  interest->setCanBePrefix(false);
  return interest;
}

bool
ClientModule::verifyProbeInfoResponse(const Data& reply)
{
  // parse the ca item
  auto contentJson = getJsonFromData(reply);
  auto caItem = ClientConfig::extractCaItem(contentJson);

  // verify the probe Data's sig
  if (!security::verifySignature(reply, caItem.m_anchor)) {
    _LOG_ERROR("Cannot verify data signature from " << m_ca.m_caName.toUri());
    return false;
  }
  return true;
}

void
ClientModule::addCaFromProbeInfoResponse(const Data& reply)
{
  // parse the ca item
  auto contentJson = getJsonFromData(reply);
  auto caItem = ClientConfig::extractCaItem(contentJson);

  // update the local config
  bool findItem = false;
  for (auto& item : m_config.m_caItems) {
    if (item.m_caName == caItem.m_caName) {
      findItem = true;
      item = caItem;
    }
  }
  if (!findItem) {
    m_config.m_caItems.push_back(caItem);
  }
}

shared_ptr<Interest>
ClientModule::generateProbeInterest(const ClientCaItem& ca, const std::string& probeInfo)
{
  Name interestName = ca.m_caName;
  interestName.append("CA").append("_PROBE");
  auto interest = make_shared<Interest>(interestName);
  interest->setMustBeFresh(true);
  interest->setCanBePrefix(false);
  auto paramJson = genProbeRequestJson(ca, probeInfo);
  interest->setApplicationParameters(paramFromJson(paramJson));

  // update local state
  m_ca = ca;
  return interest;
}

void
ClientModule::onProbeResponse(const Data& reply)
{
  if (!security::verifySignature(reply, m_ca.m_anchor)) {
    _LOG_ERROR("Cannot verify data signature from " << m_ca.m_caName.toUri());
    return;
  }
  auto contentJson = getJsonFromData(reply);

  // read the available name and put it into the state
  auto nameUri = contentJson.get(JSON_CA_NAME, "");
  if (nameUri != "") {
    m_identityName = Name(nameUri);
  }
  else {
    NDN_LOG_TRACE("The JSON_CA_NAME is empty.");
  }
}

shared_ptr<Interest>
ClientModule::generateNewInterest(const time::system_clock::TimePoint& notBefore,
                                  const time::system_clock::TimePoint& notAfter,
                                  const Name& identityName, const shared_ptr<Data>& probeToken)
{
  // Name requestedName = identityName;
  if (!identityName.empty()) { // if identityName is not empty, find the corresponding CA
    bool findCa = false;
    for (const auto& caItem : m_config.m_caItems) {
      if (caItem.m_caName.isPrefixOf(identityName)) {
        m_ca = caItem;
        findCa = true;
      }
    }
    if (!findCa) { // if cannot find, cannot proceed
      return nullptr;
    }
    m_identityName = identityName;
  }
  else { // if identityName is empty, check m_identityName or generate a random name
    if (!m_identityName.empty()) {
      // do nothing
    }
    else {
      NDN_LOG_TRACE("Randomly create a new name because m_identityName is empty and the param is empty.");
      auto id = std::to_string(random::generateSecureWord64());
      m_identityName = m_ca.m_caName;
      m_identityName.append(id);
    }
  }

  // generate a newly key pair or use an existing key
  const auto& pib = m_keyChain.getPib();
  security::pib::Identity identity;
  try {
    identity = pib.getIdentity(m_identityName);
  }
  catch (const security::Pib::Error& e) {
    identity = m_keyChain.createIdentity(m_identityName);
    m_isNewlyCreatedIdentity = true;
    m_isNewlyCreatedKey = true;
  }
  try {
    m_key = identity.getDefaultKey();
  }
  catch (const security::Pib::Error& e) {
    m_key = m_keyChain.createKey(identity);
    m_isNewlyCreatedKey = true;
  }

  // generate certificate request
  security::v2::Certificate certRequest;
  certRequest.setName(Name(m_key.getName()).append("cert-request").appendVersion());
  certRequest.setContentType(tlv::ContentType_Key);
  certRequest.setFreshnessPeriod(time::hours(24));
  certRequest.setContent(m_key.getPublicKey().data(), m_key.getPublicKey().size());
  SignatureInfo signatureInfo;
  signatureInfo.setValidityPeriod(security::ValidityPeriod(notBefore, notAfter));
  m_keyChain.sign(certRequest, signingByKey(m_key.getName()).setSignatureInfo(signatureInfo));

  // generate Interest packet
  Name interestName = m_ca.m_caName;
  interestName.append("CA").append("_NEW");
  auto interest = make_shared<Interest>(interestName);
  interest->setMustBeFresh(true);
  interest->setCanBePrefix(false);
  interest->setApplicationParameters(paramFromJson(genNewRequestJson(m_ecdh.getBase64PubKey(), certRequest, probeToken)));

  // sign the Interest packet
  m_keyChain.sign(*interest, signingByKey(m_key.getName()));
  return interest;
}

std::list<std::string>
ClientModule::onNewResponse(const Data& reply)
{
  if (!security::verifySignature(reply, m_ca.m_anchor)) {
    _LOG_ERROR("Cannot verify data signature from " << m_ca.m_caName.toUri());
    return std::list<std::string>();
  }
  auto contentJson = getJsonFromData(reply);

  // ECDH
  const auto& peerKeyBase64Str = contentJson.get(JSON_CA_ECDH, "");
  const auto& saltStr = contentJson.get(JSON_CA_SALT, "");
  uint64_t saltInt = std::stoull(saltStr);
  m_ecdh.deriveSecret(peerKeyBase64Str);

  // HKDF
  hkdf(m_ecdh.context->sharedSecret, m_ecdh.context->sharedSecretLen,
       (uint8_t*)&saltInt, sizeof(saltInt), m_aesKey, sizeof(m_aesKey));

  // update state
  m_status = contentJson.get(JSON_CA_STATUS, 0);
  m_requestId = contentJson.get(JSON_CA_REQUEST_ID, "");

  auto challengesJson = contentJson.get_child(JSON_CA_CHALLENGES);
  m_challengeList.clear();
  for (const auto& challengeJson : challengesJson) {
    m_challengeList.push_back(challengeJson.second.get(JSON_CA_CHALLENGE_ID, ""));
  }
  return m_challengeList;
}

shared_ptr<Interest>
ClientModule::generateChallengeInterest(const JsonSection& paramJson)
{
  m_challengeType = paramJson.get(JSON_CLIENT_SELECTED_CHALLENGE, "");

  Name interestName = m_ca.m_caName;
  interestName.append("CA").append("_CHALLENGE").append(m_requestId);
  auto interest = make_shared<Interest>(interestName);
  interest->setMustBeFresh(true);
  interest->setCanBePrefix(false);

  // encrypt the Interest parameters
  std::stringstream ss;
  boost::property_tree::write_json(ss, paramJson);
  auto payload = ss.str();
  auto paramBlock = genEncBlock(tlv::ApplicationParameters, m_aesKey, sizeof(m_aesKey),
                                (const uint8_t*)payload.c_str(), payload.size());
  interest->setApplicationParameters(paramBlock);

  m_keyChain.sign(*interest, signingByKey(m_key.getName()));
  return interest;
}

void
ClientModule::onChallengeResponse(const Data& reply)
{
  if (!security::verifySignature(reply, m_ca.m_anchor)) {
    _LOG_ERROR("Cannot verify data signature from " << m_ca.m_caName.toUri());
    return;
  }
  auto result = parseEncBlock(m_aesKey, sizeof(m_aesKey), reply.getContent());
  std::string payload((const char*)result.data(), result.size());
  std::istringstream ss(payload);
  JsonSection contentJson;
  boost::property_tree::json_parser::read_json(ss, contentJson);

  // update state
  m_status = contentJson.get(JSON_CA_STATUS, 0);
  m_challengeStatus = contentJson.get(JSON_CHALLENGE_STATUS, "");
  m_remainingTries = contentJson.get(JSON_CHALLENGE_REMAINING_TRIES, 0);
  m_freshBefore = time::system_clock::now() + time::seconds(contentJson.get(JSON_CHALLENGE_REMAINING_TIME, 0));
}

shared_ptr<Interest>
ClientModule::generateDownloadInterest()
{
  Name interestName = m_ca.m_caName;
  interestName.append("CA").append("_DOWNLOAD").append(m_requestId);
  auto interest = make_shared<Interest>(interestName);
  interest->setMustBeFresh(true);
  interest->setCanBePrefix(false);
  return interest;
}

shared_ptr<Interest>
ClientModule::generateCertFetchInterest()
{
  Name interestName = m_identityName;
  interestName.append("KEY").append(m_certId);
  auto interest = make_shared<Interest>(interestName);
  interest->setMustBeFresh(true);
  interest->setCanBePrefix(false);
  return interest;
}

shared_ptr<security::v2::Certificate>
ClientModule::onDownloadResponse(const Data& reply)
{
  try {
    security::v2::Certificate cert(reply.getContent().blockFromValue());
    m_keyChain.addCertificate(m_key, cert);
    _LOG_TRACE("Got DOWNLOAD response and installed the cert " << cert.getName());
    m_isCertInstalled = true;
    return make_shared<security::v2::Certificate>(cert);
  }
  catch (const std::exception& e) {
    _LOG_ERROR("Cannot add replied certificate into the keychain " << e.what());
    return nullptr;
  }
}

shared_ptr<Interest>
ClientModule::generateRevokeInterest(const security::v2::Certificate& certificate)
{
    // Name requestedName = identityName;
    bool findCa = false;
    for (const auto& caItem : m_config.m_caItems) {
        if (caItem.m_caName.isPrefixOf(certificate.getName())) {
            m_ca = caItem;
            findCa = true;
        }
    }
    if (!findCa) { // if cannot find, cannot proceed
        _LOG_TRACE("Cannot find corresponding CA for the certificate.");
        return nullptr;
    }

    // generate Interest packet
    Name interestName = m_ca.m_caName;
    interestName.append("CA").append("_REVOKE");
    auto interest = make_shared<Interest>(interestName);
    interest->setMustBeFresh(true);
    interest->setCanBePrefix(false);
    interest->setApplicationParameters(paramFromJson(genRevokeRequestJson(m_ecdh.getBase64PubKey(), certificate)));

    // return the Interest packet
    return interest;
}

std::list<std::string>
ClientModule::onRevokeResponse(const Data& reply)
{
    if (!security::verifySignature(reply, m_ca.m_anchor)) {
        _LOG_ERROR("Cannot verify data signature from " << m_ca.m_caName.toUri());
        return std::list<std::string>();
    }
    auto contentJson = getJsonFromData(reply);

    // ECDH
    const auto& peerKeyBase64Str = contentJson.get(JSON_CA_ECDH, "");
    const auto& saltStr = contentJson.get(JSON_CA_SALT, "");
    uint64_t saltInt = std::stoull(saltStr);
    m_ecdh.deriveSecret(peerKeyBase64Str);

    // HKDF
    hkdf(m_ecdh.context->sharedSecret, m_ecdh.context->sharedSecretLen,
         (uint8_t*)&saltInt, sizeof(saltInt), m_aesKey, sizeof(m_aesKey));

    // update state
    m_status = contentJson.get(JSON_CA_STATUS, 0);
    m_requestId = contentJson.get(JSON_CA_REQUEST_ID, "");

    auto challengesJson = contentJson.get_child(JSON_CA_CHALLENGES);
    m_challengeList.clear();
    for (const auto& challengeJson : challengesJson) {
        m_challengeList.push_back(challengeJson.second.get(JSON_CA_CHALLENGE_ID, ""));
    }
    return m_challengeList;
}

void
ClientModule::onCertFetchResponse(const Data& reply)
{
  onDownloadResponse(reply);
}

void
ClientModule::endSession()
{
  if (getApplicationStatus() == STATUS_SUCCESS || getApplicationStatus() == STATUS_ENDED) {
    return;
  }
  if (m_isNewlyCreatedIdentity) {
    // put the identity into the if scope is because it may cause an error
    // outside since when endSession is called, identity may not have been created yet.
    auto identity = m_keyChain.getPib().getIdentity(m_identityName);
    m_keyChain.deleteIdentity(identity);
  }
  else if (m_isNewlyCreatedKey) {
    auto identity = m_keyChain.getPib().getIdentity(m_identityName);
    m_keyChain.deleteKey(identity, m_key);
  }
  m_status = STATUS_ENDED;
}

JsonSection
ClientModule::getJsonFromData(const Data& data)
{
  std::istringstream ss(encoding::readString(data.getContent()));
  JsonSection json;
  boost::property_tree::json_parser::read_json(ss, json);
  return json;
}

std::vector<std::string>
ClientModule::parseProbeComponents(const std::string& probe)
{
  std::vector<std::string> components;
  std::string delimiter = ":";
  size_t last = 0;
  size_t next = 0;
  while ((next = probe.find(delimiter, last)) != std::string::npos) {
    components.push_back(probe.substr(last, next - last));
    last = next + 1;
  }
  components.push_back(probe.substr(last));
  return components;
}

const JsonSection
ClientModule::genProbeRequestJson(const ClientCaItem& ca, const std::string& probeInfo)
{
  JsonSection root;
  std::vector<std::string> fields = parseProbeComponents(ca.m_probe);
  std::vector<std::string> arguments  = parseProbeComponents(probeInfo);;

  if (arguments.size() != fields.size()) {
    BOOST_THROW_EXCEPTION(Error("Error in genProbeRequestJson: argument list does not match field list in the config file."));
  }
  for (size_t i = 0; i < fields.size(); ++i) {
      root.put(fields.at(i), arguments.at(i));
  }
  return root;
}

const JsonSection
ClientModule::genNewRequestJson(const std::string& ecdhPub, const security::v2::Certificate& certRequest,
                                const shared_ptr<Data>& probeToken)
{
  JsonSection root;
  std::stringstream ss;
  try {
    security::transform::bufferSource(certRequest.wireEncode().wire(), certRequest.wireEncode().size())
    >> security::transform::base64Encode(false)
    >> security::transform::streamSink(ss);
  }
  catch (const security::transform::Error& e) {
    _LOG_ERROR("Cannot convert self-signed cert into BASE64 string " << e.what());
    return root;
  }
  root.put(JSON_CLIENT_ECDH, ecdhPub);
  root.put(JSON_CLIENT_CERT_REQ, ss.str());
  if (probeToken != nullptr) {
    // clear the stringstream
    ss.str("");
    ss.clear();
    // transform the probe data into a base64 string
    try {
      security::transform::bufferSource(probeToken->wireEncode().wire(), probeToken->wireEncode().size())
      >> security::transform::base64Encode(false)
      >> security::transform::streamSink(ss);
    }
    catch (const security::transform::Error& e) {
      _LOG_ERROR("Cannot convert self-signed cert into BASE64 string " << e.what());
      return root;
    }
    // add the token into the JSON
    root.put("probe-token", ss.str());
  }
  return root;
}

const JsonSection
ClientModule::genRevokeRequestJson(const std::string& ecdhPub, const security::v2::Certificate& certificate)
{
    JsonSection root;
    std::stringstream ss;
    try {
        security::transform::bufferSource(certificate.wireEncode().wire(), certificate.wireEncode().size())
                >> security::transform::base64Encode(false)
                >> security::transform::streamSink(ss);
    }
    catch (const security::transform::Error& e) {
        _LOG_ERROR("Cannot convert self-signed cert into BASE64 string " << e.what());
        return root;
    }
    root.put(JSON_CLIENT_ECDH, ecdhPub);
    root.put(JSON_CLIENT_CERT_REVOKE, ss.str());
    return root;
}

Block
ClientModule::paramFromJson(const JsonSection& json)
{
  std::stringstream ss;
  boost::property_tree::write_json(ss, json);
  return makeStringBlock(ndn::tlv::ApplicationParameters, ss.str());
}

} // namespace ndncert
} // namespace ndn
