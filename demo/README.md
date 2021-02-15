# Operant Demo

This demo demonstrates the use of ndncert with multisignature and dledger. 

## Signers
To complete the multisignature, we need to set up signers for verify the certificate request challenge.

```shell
./demo/ndncert-signer /ndncert-mps/a/KEY/1234
./demo/ndncert-signer /ndncert-mps/b/KEY/4321
```

## Anchor Server
```shell
./tests/ndncert-ca-server -c <ca-config> -d <dledger-config>
```

## Dledger Peers

(Working directory in dledger build)
```shell
./test/dledger-impl-test test-a
./test/dledger-impl-test test-b
./test/dledger-impl-test test-c
./test/dledger-impl-test test-d
./test/dledger-impl-test test-e
```

## Initiators

```shell
./demo/demo-client <challenge-config> <ca-config>
```