//
// Created by Tyler on 2/15/21.
//
#include <cstdio>
#include <ndnmps/players.hpp>
#include <challenge/challenge-mps-possession.hpp>
#include <boost/asio/io_context.hpp>
#include <requester-request.hpp>
#include <detail/ndncert-common.hpp>
#include <detail/ca-configuration.hpp>

using namespace ndn;

void onTimeout(const Interest& interest) {
  printf("Interest Timeout for %s.\n", interest.getName().toUri().c_str());
  exit(1);
}
void onNack(const Interest& interest, const lp::Nack nack) {
  std::stringstream ss;
  ss << nack.getReason();
  printf("Interest Nack for %s with %s.\n", interest.getName().toUri().c_str(), ss.str().c_str());
  exit(1);
}

int main(int argc, char **args) {

  if (argc < 3) {
    fprintf(stderr, "Please provide configuration files\n");
    return 1;
  }
  ndn::ndncert::ChallengeMpsPossession challenge(args[1]);
  challenge.parseConfigFile();


  KeyChain keyChain;
  ndncert::CaProfile profile;
  {
    ndncert::ca::CaConfig config;
    config.load(args[2]);
    profile = config.caProfile;
    profile.cert = make_shared<security::Certificate>(keyChain.getPib().getIdentity(profile.caPrefix)
                                                .getDefaultKey().getDefaultCertificate());
  }
  boost::asio::io_service ioService;
  Face face(ioService);
  Scheduler scheduler(ioService);
  MpsSigner signer("/ndncert-mps/initiator/KEY/4135");
  ndn::Initiator initiator(challenge.m_verifier, "/ndncert-mps/initiator", face, scheduler, signer);
  for (const auto& i : challenge.m_verifier.getCerts()) {
    printf("Cert: %s\n", i.first.toUri().c_str());
    initiator.addSigner(i.first, i.first.getSubName(0, 2));
  }

  face.processEvents(time::milliseconds(100)); //TODO make smaller

  //sign the data
  auto cert = make_shared<security::Certificate>(signer.getSelfSignCert(security::ValidityPeriod(time::system_clock::now() - time::days(1),
                                                              time::system_clock::now() + time::days(365))));
  shared_ptr<Data> signerList;
  initiator.multiPartySign(challenge.m_schema, cert,
                           [&](std::shared_ptr<Data> data, Data signers) {
                             cert = make_shared<security::Certificate>(*data);
                             signerList = make_shared<Data>(signers);
                             printf("Signing done. Now try to request a certificate.\n");
                           },
                           [&](std::string s) {
                             printf("Fail to sign the credential from the signers, %s\n", s.c_str());
                           });

  while (!signerList) {
    face.processEvents(time::milliseconds(1000));
  }

  shared_ptr<security::Certificate> issuedCert;
  ndncert::requester::Request request(keyChain, profile, ndn::ndncert::RequestType::NEW);
  {
    //initiate signing with ndncert now
    auto newInterest = request.genNewInterest("/dledger/test-e", time::system_clock::now() - time::seconds(1),
                                              time::system_clock::now() + time::days(7));
    face.expressInterest(*newInterest, [&](const Interest &interest, const Data &data) {
      const auto &challenges = request.onNewRenewRevokeResponse(data);
      printf("NEW done. Now try to satisfy the ndncert challenge with the multisig credential\n");

      auto params = request.selectOrContinueChallenge("mps-possession");
      ndn::ndncert::ChallengeMpsPossession::fulfillParameters(params, *cert, *signerList,
                                                              signer, request.nonce);
      auto challengeInterest1 = request.genChallengeInterest(std::move(params));
      face.expressInterest(*challengeInterest1, [&](const Interest &interest, const Data &data) {
        request.onChallengeResponse(data);
        printf("CHALLENGE step 1 done. We also need to prove we have the private key of multisig cert.\n");

        //TODO select challenge and complete the action
        auto params = request.selectOrContinueChallenge("mps-possession");
        ndn::ndncert::ChallengeMpsPossession::fulfillParameters(params, *cert, *signerList,
                                                                signer, request.nonce);
        auto challengeInterest2 = request.genChallengeInterest(std::move(params));
        face.expressInterest(*challengeInterest2, [&](const Interest &interest, const Data &data) {
          request.onChallengeResponse(data);
          printf("CHALLENGE step 2 done\n");
          std::stringstream ss;
          ss << "RequestStatus: " << statusToString(request.status) << std::endl;
          printf("%s", ss.str().c_str());
          printf("IssuedCertName: %s\n", request.issuedCertName.toUri().c_str());
        }, onNack, onTimeout);
      }, onNack, onTimeout);
    }, onNack, onTimeout);
  }

  while (request.status != ndncert::Status::SUCCESS) {
    face.processEvents(time::milliseconds(1000));
  }

  //fetch certificate
  while (!issuedCert) {
    Interest fetchInterest(request.issuedCertName, time::milliseconds(100));
    face.expressInterest(fetchInterest, [&](const Interest &interest, const Data &data) {
      printf("Certificate Fetch done\n");
      issuedCert = make_shared<security::Certificate>(data);
    }, [](const Interest& interest, const lp::Nack nack) {
      std::stringstream ss;
      ss << nack.getReason();
      printf("Interest Nack for %s with %s.\n", interest.getName().toUri().c_str(), ss.str().c_str());
    }, [](const Interest& interest) {
      printf("Interest Timeout for %s.\n", interest.getName().toUri().c_str());
    });
    face.processEvents(time::milliseconds(200));
  }

  printf("Press any key to start revocation: ");
  getchar();

  bool r2Done = false;
  ndncert::requester::Request revokeRequest(keyChain, profile, ndn::ndncert::RequestType::REVOKE);
  {
    //initiate revoke with ndncert now
    auto newInterest = revokeRequest.genRevokeInterest(*issuedCert);
    face.expressInterest(*newInterest, [&](const Interest &interest, const Data &data) {
      const auto &challenges = revokeRequest.onNewRenewRevokeResponse(data);
      printf("REVOKE done. Now try to satisfy the ndncert challenge with the multisig credential\n");

      auto params = revokeRequest.selectOrContinueChallenge("mps-possession");
      ndn::ndncert::ChallengeMpsPossession::fulfillParameters(params, *cert, *signerList,
                                                              signer, revokeRequest.nonce);
      auto challengeInterest1 = revokeRequest.genChallengeInterest(std::move(params));
      face.expressInterest(*challengeInterest1, [&](const Interest &interest, const Data &data) {
        revokeRequest.onChallengeResponse(data);
        printf("REVOKE: CHALLENGE step 1 done. We also need to prove we have the private key of multisig cert.\n");

        auto params = revokeRequest.selectOrContinueChallenge("mps-possession");
        ndn::ndncert::ChallengeMpsPossession::fulfillParameters(params, *cert, *signerList,
                                                                signer, revokeRequest.nonce);
        auto challengeInterest2 = revokeRequest.genChallengeInterest(std::move(params));
        face.expressInterest(*challengeInterest2, [&](const Interest &interest, const Data &data) {
          revokeRequest.onChallengeResponse(data);
          printf("REVOKE: CHALLENGE step 2 done\n");
          std::stringstream ss;
          ss << "RequestStatus: " << statusToString(revokeRequest.status) << std::endl;
          printf("%s", ss.str().c_str());
          r2Done = true;
        }, onNack, onTimeout);
      }, onNack, onTimeout);
    }, onNack, onTimeout);
  }

  while (!r2Done) {
    face.processEvents(time::milliseconds(1000));
  }
}