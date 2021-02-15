/*
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

#include "challenge-mps-possession.hpp"
#include <ndn-cxx/security/verification-helpers.hpp>
#include <ndn-cxx/security/signing-helpers.hpp>
#include <ndn-cxx/security/transform/public-key.hpp>
#include <ndn-cxx/util/io.hpp>
#include <ndn-cxx/util/random.hpp>

namespace ndn {
namespace ndncert {

NDN_LOG_INIT(ndncert.challenge.mps.possession);
NDNCERT_REGISTER_CHALLENGE(ChallengeMpsPossession, "mps-possession");

const std::string ChallengeMpsPossession::PARAMETER_KEY_CREDENTIAL_CERT = "issued-cert";
const std::string ChallengeMpsPossession::PARAMETER_KEY_SIGNER_LIST = "signer-list";
const std::string ChallengeMpsPossession::PARAMETER_KEY_NONCE = "nonce";
const std::string ChallengeMpsPossession::PARAMETER_KEY_PROOF = "proof";
const std::string ChallengeMpsPossession::NEED_PROOF = "need-proof";

const std::string CONFIG_SIGNER_LIST = "signer-list";
const std::string CONFIG_MPS_SCHEMA = "mps-schema";

ChallengeMpsPossession::ChallengeMpsPossession(const std::string& configPath)
    : ChallengeModule("mps-possession", 1, time::seconds(60))
{
  if (configPath.empty()) {
    m_configFile = "mps-possession-challenge.conf.sample";//std::string(NDNCERT_SYSCONFDIR) + "/ndncert/challenge-credential.conf";
  }
  else {
    m_configFile = configPath;
  }
}

void
ChallengeMpsPossession::parseConfigFile()
{
  JsonSection config;
  try {
    boost::property_tree::read_json(m_configFile, config);
  }
  catch (const boost::property_tree::info_parser_error& error) {
    NDN_THROW(std::runtime_error("Failed to parse configuration file " + m_configFile +
                                             " " + error.message() + " line " + std::to_string(error.line())));
  }

  if (config.begin() == config.end()) {
    NDN_THROW(std::runtime_error("Error processing configuration file: " + m_configFile + " no data"));
  }

  m_verifier.getSignerLists().clear();
  auto anchorList = config.get_child(CONFIG_SIGNER_LIST);
  auto it = anchorList.begin();
  for (; it != anchorList.end(); it++) {
    std::istringstream ss(it->second.get("certificate", ""));
    auto cert = io::load<security::Certificate>(ss);
    if (cert == nullptr) {
      NDN_LOG_ERROR("Cannot load the certificate from config file");
      continue;
    }
    m_verifier.addCert(*cert);
  }

  auto schemaSection = config.get_child(CONFIG_MPS_SCHEMA);
  std::stringstream ss;
  boost::property_tree::write_info(ss, schemaSection);
  m_schema = MultipartySchema::fromINFO(ss.str());
}

// For CA
std::tuple<ErrorCode, std::string>
ChallengeMpsPossession::handleChallengeRequest(const Block& params, ca::RequestState& request) {
  params.parse();
  if (m_verifier.getCerts().empty()) {
    parseConfigFile();
  }

  //possible elements
  security::Certificate credential;
  const uint8_t *signature = nullptr;
  size_t signatureLen = 0;
  Name signerListName;
  MpsSignerList signerList;

  const auto &elements = params.elements();
  for (size_t i = 0; i < elements.size() - 1; i++) {
    if (elements[i].type() == tlv::ParameterKey && elements[i + 1].type() == tlv::ParameterValue) {
      if (readString(elements[i]) == PARAMETER_KEY_CREDENTIAL_CERT) {
        try {
          credential.wireDecode(elements[i + 1].blockFromValue());
        }
        catch (const std::exception &e) {
          NDN_LOG_ERROR("Cannot load challenge parameter: credential " << e.what());
          return returnWithError(request, ErrorCode::INVALID_PARAMETER,
                                 "Cannot challenge credential: credential." + std::string(e.what()));
        }
      } else if (readString(elements[i]) == PARAMETER_KEY_PROOF) {
        signature = elements[i + 1].value();
        signatureLen = elements[i + 1].value_size();
      } else if (readString(elements[i]) == PARAMETER_KEY_SIGNER_LIST) {
        try {
          Data d = Data(elements[i + 1].blockFromValue());
          const auto &content = d.getContent();
          content.parse();
          signerListName = d.getName();
          signerList = content.get(ndn::tlv::MpsSignerList);
        }
        catch (const std::exception &e) {
          NDN_LOG_ERROR("Cannot load challenge parameter: signer list " << e.what());
          return returnWithError(request, ErrorCode::INVALID_PARAMETER,
                                 "Cannot challenge parameter: signer list." + std::string(e.what()));
        }
      }
      i ++;
    }
  }

  // verify the credential with signer list
  if (request.status == Status::BEFORE_CHALLENGE) {
    NDN_LOG_TRACE("Challenge Interest arrives. Check certificate and init the challenge");
    // check the existence of certificate
    if (!(credential.hasContent() && signatureLen == 0)) {
      return returnWithError(request, ErrorCode::BAD_INTEREST_FORMAT, "Cannot find credential in interest");
    }

    //verify credential format
    const auto &pubKeyBuffer = credential.getPublicKey();
    try {
      security::transform::PublicKey key;
      key.loadPkcs8(pubKeyBuffer.data(), pubKeyBuffer.size());
    } catch (const std::exception &e) {
      blsPublicKey k;
      if (blsPublicKeyDeserialize(&k, pubKeyBuffer.data(), pubKeyBuffer.size()) == 0) {
        return returnWithError(request, ErrorCode::BAD_INTEREST_FORMAT, "Bad public key");
      }
    }

    //check signer list
    m_verifier.getSignerLists().clear();
    m_verifier.addSignerList(signerListName, signerList);

    for (const auto &i : signerList) {
      if (m_verifier.getCerts().count(i) == 0)
        return returnWithError(request, ErrorCode::BAD_INTEREST_FORMAT, "Cannot find certificate");
    }

    //verify signature
    if (!m_verifier.verifySignature(credential, m_schema)) {
      return returnWithError(request, ErrorCode::INVALID_PARAMETER, "Certificate cannot be verified");
    }
    m_verifier.getSignerLists().clear();

    // for the first time, init the challenge
    std::array<uint8_t, 16> secretCode{};
    random::generateSecureBytes(secretCode.data(), 16);
    JsonSection secretJson;
    secretJson.add(PARAMETER_KEY_NONCE, toHex(secretCode.data(), 16));
    auto credential_block = credential.wireEncode();
    secretJson.add(PARAMETER_KEY_CREDENTIAL_CERT, toHex(credential_block.wire(), credential_block.size()));
    NDN_LOG_TRACE("Secret for request " << toHex(request.requestId.data(), request.requestId.size())
                                        << " : " << toHex(secretCode.data(), 16));
    return returnWithNewChallengeStatus(request, NEED_PROOF, std::move(secretJson), m_maxAttemptTimes,
                                        m_secretLifetime);
  } else if (request.challengeState && request.challengeState->challengeStatus == NEED_PROOF) {
    NDN_LOG_TRACE("Challenge Interest (proof) arrives. Check the proof");
    //check the format and load credential
    if (credential.hasContent() || signatureLen == 0) {
      return returnWithError(request, ErrorCode::BAD_INTEREST_FORMAT, "Cannot find certificate");
    }
    credential = security::Certificate(
        Block(fromHex(request.challengeState->secrets.get(PARAMETER_KEY_CREDENTIAL_CERT, ""))));
    auto secretCode = *fromHex(request.challengeState->secrets.get(PARAMETER_KEY_NONCE, ""));

    //check the proof
    const auto &pubKeyBuffer = credential.getPublicKey();
    try {
      security::transform::PublicKey key;
      key.loadPkcs8(pubKeyBuffer.data(), pubKeyBuffer.size());
      if (security::verifySignature(secretCode.data(), secretCode.size(), signature, signatureLen, key)) {
        return returnWithSuccess(request);
      }
    } catch (const std::exception &e) {
      blsPublicKey pubKey;
      blsSignature sig;
      if (blsPublicKeyDeserialize(&pubKey, pubKeyBuffer.data(), pubKeyBuffer.size()) == 0 ||
          blsSignatureDeserialize(&sig, signature, signatureLen) == 0) {
        return returnWithError(request, ErrorCode::INVALID_PARAMETER, "Cannot decode challenge parameter: public key.");
      }
      if (blsVerify(&sig, &pubKey, secretCode.data(), secretCode.size())) {
        return returnWithSuccess(request);
      }
    }

    //error!
    return returnWithError(request, ErrorCode::INVALID_PARAMETER,
                           "Cannot verify the proof of private key against credential.");
  }
  NDN_LOG_TRACE("Proof of possession: bad state");
  return returnWithError(request, ErrorCode::INVALID_PARAMETER, "Fail to recognize the request.");
}

// For Client
std::multimap<std::string, std::string>
ChallengeMpsPossession::getRequestedParameterList(Status status, const std::string& challengeStatus)
{
  std::multimap<std::string, std::string> result;
  if (status == Status::BEFORE_CHALLENGE) {
    result.emplace(PARAMETER_KEY_CREDENTIAL_CERT, "Please provide the certificate issued by a trusted CA.");
    result.emplace(PARAMETER_KEY_SIGNER_LIST, "Please provide the corresponding signer list for the credential.");
    return result;
  } else if (status == Status::CHALLENGE && challengeStatus == NEED_PROOF) {
    result.emplace(PARAMETER_KEY_PROOF, "Please sign a Data packet with request ID as the content.");
  } else {
    NDN_THROW(std::runtime_error("Unexpected status or challenge status."));
  }

  return result;
}

Block
ChallengeMpsPossession::genChallengeRequestTLV(Status status, const std::string& challengeStatus,
                                            const std::multimap<std::string, std::string>& params)
{
  Block request(tlv::EncryptedPayload);
  request.push_back(makeStringBlock(tlv::SelectedChallenge, CHALLENGE_TYPE));
  if (status == Status::BEFORE_CHALLENGE) {
    if (params.size() != 2) {
      NDN_THROW(std::runtime_error("Wrong parameter provided."));
    }
    for (const auto& item : params) {
      if (item.first == PARAMETER_KEY_CREDENTIAL_CERT || item.first == PARAMETER_KEY_SIGNER_LIST) {
        request.push_back(makeStringBlock(tlv::ParameterKey, item.first));
        Block valueBlock(tlv::ParameterValue);
        auto& dataTlvStr = std::get<1>(item);
        valueBlock.push_back(Block((uint8_t*)dataTlvStr.c_str(), dataTlvStr.size()));
        request.push_back(valueBlock);
      }
      else {
        NDN_THROW(std::runtime_error("Wrong parameter provided."));
      }
    }
  } else if (status == Status::CHALLENGE && challengeStatus == NEED_PROOF){
    if (params.size() != 1) {
      NDN_THROW(std::runtime_error("Wrong parameter provided."));
    }
    for (const auto &item : params) {
      if (std::get<0>(item) == PARAMETER_KEY_PROOF) {
        request.push_back(makeStringBlock(tlv::ParameterKey, PARAMETER_KEY_PROOF));
        auto &sigTlvStr = std::get<1>(item);
        Block valueBlock = makeBinaryBlock(tlv::ParameterValue, (uint8_t *) sigTlvStr.c_str(),
                                           sigTlvStr.size());
        request.push_back(valueBlock);
      } else {
        NDN_THROW(std::runtime_error("Wrong parameter provided."));
      }
    }
  } else {
    NDN_THROW(std::runtime_error("Unexpected status or challenge status."));
  }
  request.encode();
  return request;
}

void
ChallengeMpsPossession::fulfillParameters(std::multimap<std::string, std::string>& params,
                                          KeyChain& keyChain, const Name& issuedCertName, const Data& certSignerList,
                                          const std::array<uint8_t, 16>& nonce)
{
  auto& pib = keyChain.getPib();
  auto id = pib.getIdentity(security::extractIdentityFromCertName(issuedCertName));
  auto issuedCert = id.getKey(security::extractKeyNameFromCertName(issuedCertName)).getCertificate(issuedCertName);
  auto signatureTlv = keyChain.sign(nonce.data(), nonce.size(), security::signingByCertificate(issuedCertName));
  for (auto& item : params) {
    if (item.first == PARAMETER_KEY_CREDENTIAL_CERT) {
      auto issuedCertTlv = issuedCert.wireEncode();
      item.second = std::string((char*)issuedCertTlv.wire(), issuedCertTlv.size());
    }
    else if (item.first == PARAMETER_KEY_SIGNER_LIST) {
      const auto& signerListTlv = certSignerList.wireEncode();
      item.second = std::string((char*)signerListTlv.wire(), signerListTlv.size());
    }
    else if (item.first == PARAMETER_KEY_PROOF) {
      item.second = std::string((char*)signatureTlv.value(), signatureTlv.value_size());
    }
  }
}

void
ChallengeMpsPossession::fulfillParameters(std::multimap<std::string, std::string>& params,
                                          const security::Certificate& cert, const Data& certSignerList, const MpsSigner& signer,
                                          const std::array<uint8_t, 16>& nonce)
{
  for (auto& item : params) {
    if (std::get<0>(item) == PARAMETER_KEY_CREDENTIAL_CERT) {
      const auto& issuedCertTlv = cert.wireEncode();
      std::get<1>(item) = std::string((char*)issuedCertTlv.wire(), issuedCertTlv.size());
    }
    else if (std::get<0>(item) == PARAMETER_KEY_SIGNER_LIST) {
      const auto& signerListTlv = certSignerList.wireEncode();
      std::get<1>(item) = std::string((char*)signerListTlv.wire(), signerListTlv.size());
    }
    else if (std::get<0>(item) == PARAMETER_KEY_PROOF) {
      const auto& secretKey = signer.getSecretKey();
      blsSignature sig;
      blsSign(&sig, &secretKey, nonce.data(), nonce.size());
      Buffer sigBuf(blsGetSerializedSignatureByteSize());
      int outSize = blsSignatureSerialize(sigBuf.data(), sigBuf.size(), &sig);
      if (outSize == 0) {
        NDN_THROW(std::runtime_error("Cannot encode signature"));
      }
      sigBuf.resize(outSize);
      std::get<1>(item) = std::string((char*)sigBuf.data(), sigBuf.size());
    }
  }
}

} // namespace ndncert
} // namespace ndn
