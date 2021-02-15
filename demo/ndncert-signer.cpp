//
// Created by Tyler on 2/15/21.
//
#include <cstdio>
#include <ndnmps/players.hpp>
#include <boost/archive/iterators/base64_from_binary.hpp>
#include <boost/archive/iterators/transform_width.hpp>
#include <boost/archive/iterators/ostream_iterator.hpp>
using namespace ndn;

int main(int argc, char **args) {
  if (argc < 2) {
    fprintf(stderr, "Please provide signer key name argument\n");
    return 1;
  }

  if (readString(Name(args[1]).get(-2)) != "KEY") {
    fprintf(stderr, "Please provide a valid key name like /prefix/KEY/key-id\n");
    return 1;
  }

  Face face;
  auto identity = make_unique<MpsSigner>(args[1]);
  auto certBlock = identity->getSelfSignCert(security::ValidityPeriod(time::system_clock::now() - time::seconds(1),
                                                     time::system_clock::now() + time::days(366)))
                                                     .wireEncode();

  //print certificate
  std::stringstream os;
  using namespace boost::archive::iterators;
  typedef base64_from_binary<transform_width<const char *,6,8>> base64_text; // compose all the above operations in to a new iterator

  std::copy(
      base64_text(certBlock.wire()),
      base64_text(certBlock.wire() + certBlock.size()),
      ostream_iterator<char>(os)
  );

  printf("Cert: %s%s\n", os.str().c_str(), certBlock.size() % 3 == 1 ? "==" : certBlock.size() % 3 == 2 ? "=":"");

  Name prefixName = Name(args[1]);
  prefixName = prefixName.getSubName(0, prefixName.size() - 2);
  ndn::Signer signer(std::move(identity), prefixName, face);
  signer.setSignatureVerifyCallback([](const Interest& _){return true;});
  signer.setDataVerifyCallback([](const Data& _){return true;});

  face.processEvents();
}