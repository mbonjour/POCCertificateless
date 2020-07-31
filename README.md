# README for POC of certificateless encryption and signing of emails
### Author : Mickael Bonjour

## Purpose of this README
This readme is here to help building this POC from sources and explain a bit what it's going on.
## Dependencies
Steps to install on an Ubuntu-like system :

We need usual tools to build :
```bash
sudo apt-get install build-essential
sudo apt-get install cmake
```
Some libraries need to be installed before building the sources.

- Libcurl
- Libetpan
- Libsodium
- libgmp
- libbinn
- unqlite

Libbinn :
```bash
git clone https://github.com/liteserver/binn
cd binn
make
sudo make install
```
Due to how binn installs, we need to set the environment variable LD_LIBRARY_PATH to /usr/local/lib

Libsodium :
```bash
git clone https://github.com/jedisct1/libsodium --branch stable
cd libsodium
./configure
make && make check
sudo make install
```
Libcurl :
```bash
sudo apt-get install libcurl4-gnutls-dev
```
Libetpan:
```bash
sudo apt-get install autoconf libtool
git clone https://github.com/dinhvh/libetpan.git
cd libetpan
./autogen.sh
make
```
Libgmp :
```bash
sudo apt-get install libgmp-dev
```

One more step in the directory, we need to download the RELIC library source and copy it to the lib folder because we need the headers. If neede you can reompile the library with the BLS12-P381 curve and create a relic-target folder  but it's not necessary as it's already done.
```bash
cd libs
git clone https://github.com/relic-toolkit/relic.git
```

## Build and launch
To simply build from the sources you can try this command :
```bash
cmake . && make
```
And you will have an ELF executable called testAlgo, mainServer, mainClient.

You can try it yourself by first running the server and then the client. Or just try the testAlgo to see a test made for perfomences and testing a scenario.

## Purpose of the POC
The POC simply try to encrypt an AES Key with Certificateless crypto and then sign it.
Then it will encrypt a message using the AES Key. It's simply a POC, so no memory is cleaned for the AES Key, and some vulnerabilities can appear at this point.
But the POC proves just that certificateless crypto is quick and can be implemented to encrypt messages.
