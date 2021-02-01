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

#include "challenge/challenge-mps-possession.hpp"
#include "test-common.hpp"
#include "detail/challenge-encoder.hpp"

namespace ndn {
namespace ndncert {
namespace tests {

BOOST_FIXTURE_TEST_SUITE(TestChallengeMpsPossession, IdentityManagementFixture)

BOOST_AUTO_TEST_CASE(LoadMpsConfig)
{
  ChallengeMpsPossession challenge("./tests/mps-unit-tests/config-files/config-challenge-mps-possession");
  BOOST_CHECK_EQUAL(challenge.CHALLENGE_TYPE, "MpsPossession");

  challenge.parseConfigFile();
  BOOST_CHECK_EQUAL(challenge.m_verifier.getCerts().size(), 2);
  auto keyPair = challenge.m_verifier.getCerts().begin();
  BOOST_CHECK_EQUAL(keyPair->first,
                    "/a/b/c/KEY/1234");
  auto keyPair2 = keyPair;
  keyPair2 ++;
  BOOST_CHECK_EQUAL(keyPair2->first,
                    "/a/b/c/KEY/1235");

  BOOST_CHECK_EQUAL(challenge.m_schema.minOptionalSigners, 2);
  BOOST_CHECK_EQUAL(challenge.m_schema.signers.size(), 2);
  BOOST_CHECK_EQUAL(challenge.m_schema.optionalSigners.size(), 3);
  BOOST_CHECK_EQUAL(challenge.m_schema.signers[0], WildCardName("/example/a/KEY/_/_"));
  BOOST_CHECK_EQUAL(challenge.m_schema.signers[1], WildCardName("/example/b/KEY/_/_"));
  BOOST_CHECK_EQUAL(challenge.m_schema.optionalSigners[0], WildCardName("/example/c/KEY/_/_"));
  BOOST_CHECK_EQUAL(challenge.m_schema.optionalSigners[1], WildCardName("/example/d/KEY/_/_"));
  BOOST_CHECK_EQUAL(challenge.m_schema.optionalSigners[2], WildCardName("/example/e/KEY/_/_"));
}

BOOST_AUTO_TEST_CASE(HandleMpsChallengeRequest)
{
  // create challenge and trust anchor
  ChallengeMpsPossession challenge;
  auto trustA = MpsSigner("/trust/A/KEY/8888");
  auto trustB = MpsSigner("/trust/B/KEY/1234");
  challenge.m_verifier.addCert(trustA.getSignerKeyName(), trustA.getPublicKey());
  challenge.m_verifier.addCert(trustB.getSignerKeyName(), trustB.getPublicKey());
  MultipartySchema schema;
  schema.signers.emplace_back("/trust/A/KEY/_");
  schema.signers.emplace_back("/trust/B/KEY/_");
  challenge.m_schema = schema;

  // create certificate request
  auto identityA = addIdentity(Name("/example"));
  auto keyA = identityA.getDefaultKey();
  auto certA = keyA.getDefaultCertificate();
  RequestId requestId = {{101}};
  ca::RequestState state;
  state.caPrefix = Name("/example");
  state.requestId = requestId;
  state.requestType = RequestType::NEW;
  state.cert = certA;

  // create requester's credential
  auto identityB = addIdentity(Name("/trust/A/cert"));
  auto keyB = identityB.getDefaultKey();
  auto credentialName = Name(keyB.getName()).append("Credential").appendVersion();
  security::Certificate credential;
  credential.setName(credentialName);
  credential.setContent(keyB.getPublicKey().data(), keyB.getPublicKey().size());
  credential.setContentType(ndn::tlv::ContentType_Key);

  SignatureInfo signatureInfo;
  signatureInfo.setSignatureType(static_cast<ndn::tlv::SignatureTypeValue>(ndn::tlv::SignatureSha256WithBls));
  signatureInfo.setValidityPeriod(security::ValidityPeriod(time::system_clock::now() - time::seconds(1), time::system_clock::now() +
                                  time::minutes(1)));
  signatureInfo.setKeyLocator(Name("/just/a/signer/list"));
  credential.setSignatureInfo(signatureInfo);

  //sign
  {
    std::vector<blsSignature> signatures;
    auto sigA = trustA.getSignature(credential);
    auto sigB = trustB.getSignature(credential);
    blsSignature sig;
    blsSignatureDeserialize(&sig, sigA.value(), sigA.value_size());
    signatures.push_back(sig);
    blsSignatureDeserialize(&sig, sigB.value(), sigB.value_size());
    signatures.push_back(sig);
    MpsAggregator().buildMultiSignature(credential, signatures);
  }

  m_keyChain.addCertificate(keyB, credential);

  //create signer list
  Data signerListData("/just/a/signer/list");
  MpsSignerList signerList;
  signerList.push_back(trustA.getSignerKeyName());
  signerList.push_back(trustB.getSignerKeyName());
  signerListData.setContent(makeNestedBlock(ndn::tlv::Content, signerList));
  m_keyChain.sign(signerListData, signingWithSha256());

  // using private key to sign cert request
  auto params = challenge.getRequestedParameterList(state.status, "");
  ChallengeMpsPossession::fulfillParameters(params, m_keyChain, credential.getName(), signerListData, std::array<uint8_t, 16>{});
  Block paramsTlv = challenge.genChallengeRequestTLV(state.status, "", params);
  challenge.handleChallengeRequest(paramsTlv, state);
  BOOST_CHECK_EQUAL(statusToString(state.status), statusToString(Status::CHALLENGE));
  BOOST_CHECK_EQUAL(state.challengeState->challengeStatus, "need-proof");

  // reply from server
  auto nonceBuf = fromHex(state.challengeState->secrets.get("nonce", ""));
  std::array<uint8_t, 16> nonce{};
  memcpy(nonce.data(), nonceBuf->data(), 16);
  auto params2 = challenge.getRequestedParameterList(state.status, state.challengeState->challengeStatus);
  ChallengeMpsPossession::fulfillParameters(params2, m_keyChain, credential.getName(), signerListData, nonce);
  Block paramsTlv2 = challenge.genChallengeRequestTLV(state.status, state.challengeState->challengeStatus, params2);
  challenge.handleChallengeRequest(paramsTlv2, state);
  BOOST_CHECK_EQUAL(statusToString(state.status), statusToString(Status::PENDING));
}

BOOST_AUTO_TEST_CASE(HandleMpsChallengeRequestWithMpsProof)
{
  // create challenge and trust anchor
  ChallengeMpsPossession challenge;
  auto trustA = MpsSigner("/trust/A/KEY/8888");
  auto trustB = MpsSigner("/trust/B/KEY/1234");
  challenge.m_verifier.addCert(trustA.getSignerKeyName(), trustA.getPublicKey());
  challenge.m_verifier.addCert(trustB.getSignerKeyName(), trustB.getPublicKey());
  MultipartySchema schema;
  schema.signers.emplace_back("/trust/A/KEY/_");
  schema.signers.emplace_back("/trust/B/KEY/_");
  challenge.m_schema = schema;

  // create certificate request
  auto identityA = addIdentity(Name("/example"));
  auto keyA = identityA.getDefaultKey();
  auto certA = keyA.getDefaultCertificate();
  RequestId requestId = {{101}};
  ca::RequestState state;
  state.caPrefix = Name("/example");
  state.requestId = requestId;
  state.requestType = RequestType::NEW;
  state.cert = certA;

  // create requester's credential
  auto credentialSigner = MpsSigner(Name("/trust/A/cert/KEY/124"));
  auto credentialName = Name(credentialSigner.getSignerKeyName()).append("Credential").appendVersion();
  security::Certificate credential;
  credential.setName(credentialName);
  credential.setContent(credentialSigner.getpublicKeyStr().data(), credentialSigner.getpublicKeyStr().size());
  credential.setContentType(ndn::tlv::ContentType_Key);

  SignatureInfo signatureInfo;
  signatureInfo.setSignatureType(static_cast<ndn::tlv::SignatureTypeValue>(ndn::tlv::SignatureSha256WithBls));
  signatureInfo.setValidityPeriod(security::ValidityPeriod(time::system_clock::now() - time::seconds(1), time::system_clock::now() +
                                                                                                              time::minutes(1)));
  signatureInfo.setKeyLocator(Name("/just/a/signer/list"));
  credential.setSignatureInfo(signatureInfo);

  //sign
  {
    std::vector<blsSignature> signatures;
    auto sigA = trustA.getSignature(credential);
    auto sigB = trustB.getSignature(credential);
    blsSignature sig;
    blsSignatureDeserialize(&sig, sigA.value(), sigA.value_size());
    signatures.push_back(sig);
    blsSignatureDeserialize(&sig, sigB.value(), sigB.value_size());
    signatures.push_back(sig);
    MpsAggregator().buildMultiSignature(credential, signatures);
  }

  //create signer list
  Data signerListData("/just/a/signer/list");
  MpsSignerList signerList;
  signerList.push_back(trustA.getSignerKeyName());
  signerList.push_back(trustB.getSignerKeyName());
  signerListData.setContent(makeNestedBlock(ndn::tlv::Content, signerList));
  m_keyChain.sign(signerListData, signingWithSha256());

  // using private key to sign cert request
  auto params = challenge.getRequestedParameterList(state.status, "");
  ChallengeMpsPossession::fulfillParameters(params, credential, signerListData, credentialSigner, std::array<uint8_t, 16>{});
  Block paramsTlv = challenge.genChallengeRequestTLV(state.status, "", params);
  challenge.handleChallengeRequest(paramsTlv, state);
  BOOST_CHECK_EQUAL(statusToString(state.status), statusToString(Status::CHALLENGE));
  BOOST_CHECK_EQUAL(state.challengeState->challengeStatus, "need-proof");

  // reply from server
  auto nonceBuf = fromHex(state.challengeState->secrets.get("nonce", ""));
  std::array<uint8_t, 16> nonce{};
  memcpy(nonce.data(), nonceBuf->data(), 16);
  auto params2 = challenge.getRequestedParameterList(state.status, state.challengeState->challengeStatus);
  ChallengeMpsPossession::fulfillParameters(params2, credential, signerListData, credentialSigner, nonce);
  Block paramsTlv2 = challenge.genChallengeRequestTLV(state.status, state.challengeState->challengeStatus, params2);
  challenge.handleChallengeRequest(paramsTlv2, state);
  BOOST_CHECK_EQUAL(statusToString(state.status), statusToString(Status::PENDING));
}

BOOST_AUTO_TEST_CASE(HandleMpsChallengeBadRequest)
{
  // create challenge and trust anchor
  ChallengeMpsPossession challenge;
  auto trustA = MpsSigner("/trust/A/KEY/8888");
  auto trustB = MpsSigner("/trust/B/KEY/1234");
  challenge.m_verifier.addCert(trustA.getSignerKeyName(), trustA.getPublicKey());
  challenge.m_verifier.addCert(trustB.getSignerKeyName(), trustB.getPublicKey());
  MultipartySchema schema;
  schema.signers.emplace_back("/trust/A/KEY/_");
  schema.signers.emplace_back("/trust/B/KEY/_");
  challenge.m_schema = schema;

  // create certificate request
  auto identityA = addIdentity(Name("/example"));
  auto keyA = identityA.getDefaultKey();
  auto certA = keyA.getDefaultCertificate();
  RequestId requestId = {{101}};
  ca::RequestState state;
  state.caPrefix = Name("/example");
  state.requestId = requestId;
  state.requestType = RequestType::NEW;
  state.cert = certA;

  // create requester's credential
  auto identityB = addIdentity(Name("/trust/A/cert"));
  auto keyB = identityB.getDefaultKey();
  auto credentialName = Name(keyB.getName()).append("Credential").appendVersion();
  security::Certificate credential;
  credential.setName(credentialName);
  credential.setContent(keyB.getPublicKey().data(), keyB.getPublicKey().size());
  credential.setContentType(ndn::tlv::ContentType_Key);

  SignatureInfo signatureInfo;
  signatureInfo.setSignatureType(static_cast<ndn::tlv::SignatureTypeValue>(ndn::tlv::SignatureSha256WithBls));
  signatureInfo.setValidityPeriod(security::ValidityPeriod(time::system_clock::now() - time::seconds(1), time::system_clock::now() +
                                                                                                         time::minutes(1)));
  signatureInfo.setKeyLocator(Name("/just/a/signer/list"));
  credential.setSignatureInfo(signatureInfo);

  //sign
  {
    std::vector<blsSignature> signatures;
    auto sigA = trustA.getSignature(credential);
    auto sigB = trustB.getSignature(credential);
    blsSignature sig;
    blsSignatureDeserialize(&sig, sigA.value(), sigA.value_size());
    signatures.push_back(sig);
    blsSignatureDeserialize(&sig, sigB.value(), sigB.value_size());
    signatures.push_back(sig);
    MpsAggregator().buildMultiSignature(credential, signatures);
  }

  m_keyChain.addCertificate(keyB, credential);

  //create signer list
  Data signerListData("/just/a/signer/list");
  MpsSignerList signerList;
  signerList.push_back(trustA.getSignerKeyName());
  signerList.push_back(trustB.getSignerKeyName());
  signerListData.setContent(makeNestedBlock(ndn::tlv::Content, signerList));
  m_keyChain.sign(signerListData, signingWithSha256());

  // using private key to sign cert request
  auto params = challenge.getRequestedParameterList(state.status, "");
  ChallengeMpsPossession::fulfillParameters(params, m_keyChain, credential.getName(), signerListData, std::array<uint8_t, 16>{});
  Block paramsTlv = challenge.genChallengeRequestTLV(state.status, "", params);
  challenge.handleChallengeRequest(paramsTlv, state);
  BOOST_CHECK_EQUAL(statusToString(state.status), statusToString(Status::CHALLENGE));
  BOOST_CHECK_EQUAL(state.challengeState->challengeStatus, "need-proof");

  // reply from server
  auto nonceBuf = fromHex(state.challengeState->secrets.get("nonce", ""));
  std::array<uint8_t, 16> nonce{};
  memcpy(nonce.data(), nonceBuf->data(), 16);
  nonce[2] = 112;
  auto params2 = challenge.getRequestedParameterList(state.status, state.challengeState->challengeStatus);
  ChallengeMpsPossession::fulfillParameters(params2, m_keyChain, credential.getName(), signerListData, nonce);
  Block paramsTlv2 = challenge.genChallengeRequestTLV(state.status, state.challengeState->challengeStatus, params2);
  challenge.handleChallengeRequest(paramsTlv2, state);
  BOOST_CHECK_EQUAL(statusToString(state.status), statusToString(Status::FAILURE));
}

BOOST_AUTO_TEST_CASE(HandleMpsChallengeBadRequestWithMpsProof)
{
  // create challenge and trust anchor
  ChallengeMpsPossession challenge;
  auto trustA = MpsSigner("/trust/A/KEY/8888");
  auto trustB = MpsSigner("/trust/B/KEY/1234");
  challenge.m_verifier.addCert(trustA.getSignerKeyName(), trustA.getPublicKey());
  challenge.m_verifier.addCert(trustB.getSignerKeyName(), trustB.getPublicKey());
  MultipartySchema schema;
  schema.signers.emplace_back("/trust/A/KEY/_");
  schema.signers.emplace_back("/trust/B/KEY/_");
  challenge.m_schema = schema;

  // create certificate request
  auto identityA = addIdentity(Name("/example"));
  auto keyA = identityA.getDefaultKey();
  auto certA = keyA.getDefaultCertificate();
  RequestId requestId = {{101}};
  ca::RequestState state;
  state.caPrefix = Name("/example");
  state.requestId = requestId;
  state.requestType = RequestType::NEW;
  state.cert = certA;

  // create requester's credential
  auto credentialSigner = MpsSigner(Name("/trust/A/cert/KEY/124"));
  auto credentialName = Name(credentialSigner.getSignerKeyName()).append("Credential").appendVersion();
  security::Certificate credential;
  credential.setName(credentialName);
  credential.setContent(credentialSigner.getpublicKeyStr().data(), credentialSigner.getpublicKeyStr().size());
  credential.setContentType(ndn::tlv::ContentType_Key);

  SignatureInfo signatureInfo;
  signatureInfo.setSignatureType(static_cast<ndn::tlv::SignatureTypeValue>(ndn::tlv::SignatureSha256WithBls));
  signatureInfo.setValidityPeriod(security::ValidityPeriod(time::system_clock::now() - time::seconds(1), time::system_clock::now() +
                                                                                                         time::minutes(1)));
  signatureInfo.setKeyLocator(Name("/just/a/signer/list"));
  credential.setSignatureInfo(signatureInfo);

  //sign
  {
    std::vector<blsSignature> signatures;
    auto sigA = trustA.getSignature(credential);
    auto sigB = trustB.getSignature(credential);
    blsSignature sig;
    blsSignatureDeserialize(&sig, sigA.value(), sigA.value_size());
    signatures.push_back(sig);
    blsSignatureDeserialize(&sig, sigB.value(), sigB.value_size());
    signatures.push_back(sig);
    MpsAggregator().buildMultiSignature(credential, signatures);
  }

  //create signer list
  Data signerListData("/just/a/signer/list");
  MpsSignerList signerList;
  signerList.push_back(trustA.getSignerKeyName());
  signerList.push_back(trustB.getSignerKeyName());
  signerListData.setContent(makeNestedBlock(ndn::tlv::Content, signerList));
  m_keyChain.sign(signerListData, signingWithSha256());

  // using private key to sign cert request
  auto params = challenge.getRequestedParameterList(state.status, "");
  ChallengeMpsPossession::fulfillParameters(params, credential, signerListData, credentialSigner, std::array<uint8_t, 16>{});
  Block paramsTlv = challenge.genChallengeRequestTLV(state.status, "", params);
  challenge.handleChallengeRequest(paramsTlv, state);
  BOOST_CHECK_EQUAL(statusToString(state.status), statusToString(Status::CHALLENGE));
  BOOST_CHECK_EQUAL(state.challengeState->challengeStatus, "need-proof");

  // reply from server
  auto nonceBuf = fromHex(state.challengeState->secrets.get("nonce", ""));
  std::array<uint8_t, 16> nonce{};
  memcpy(nonce.data(), nonceBuf->data(), 16);
  nonce[2] = 112;
  auto params2 = challenge.getRequestedParameterList(state.status, state.challengeState->challengeStatus);
  ChallengeMpsPossession::fulfillParameters(params2, credential, signerListData, credentialSigner, nonce);
  Block paramsTlv2 = challenge.genChallengeRequestTLV(state.status, state.challengeState->challengeStatus, params2);
  challenge.handleChallengeRequest(paramsTlv2, state);
  BOOST_CHECK_EQUAL(statusToString(state.status), statusToString(Status::FAILURE));
}

BOOST_AUTO_TEST_SUITE_END()

} // namespace tests
} // namespace ndncert
} // namespace ndn
