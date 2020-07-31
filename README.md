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
git clone https://github.com/dinhvh/libetpan.git
cd libetpan
./autogen.sh
make
```
Libgmp :
```bash
sudo apt-get install libgmp-dev
```

One more step, we need to download the RELIC library source and copy it to the lib folder :
```bash
cd libs
git clone https://github.com/relic-toolkit/relic.git
```
## Build and launch
To simply build from the sources you can try this command :
```bash
cmake . && make
```
And you will have an ELF executable called Test_RELIC.

## Purpose of the POC
The POC simply try to encrypt an AES Key with Certificateless crypto and then sign it.
Then it will encrypt a message using the AES Key. It's simply a POC, so no memory is cleaned for the AES Key, and some vulnerabilities can appear at this point.
But the POC proves just that certificateless crypto is quick and can be implemented to encrypt messages.
