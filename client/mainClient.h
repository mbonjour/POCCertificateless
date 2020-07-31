/**
 * @file mainClient.h
 * @author Mickael Bonjour mickael.bonjour@heig-vd.ch
 * @date 14 juillet 2020
 * @brief This is the main file for the client side application of my project POC.
 *        It's able to communicate with the KGC and the gmail servers to send encrypted mails and receive them.
 *        This file will ask for infos about the user along the way and store some infos, the most sensitive encrypted.
 *        It's really the core of the POC but needs to be initialized with a KGC running.
 */

#ifndef POCCERTIFICATELESSCRYPTOGRAPHY_MAINCLIENT_H
#define POCCERTIFICATELESSCRYPTOGRAPHY_MAINCLIENT_H
#include <sodium.h>
#include <stdio.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <string.h>
#include <curl/curl.h>
#include <time.h>
#include <libetpan/libetpan.h>
#include <dirent.h>

#include "utils/base64.h"
#include "utils/socketUtils.h"
#include "cipherPOC.h"
#include "signaturePOC.h"
#include "utils/aesUtils.h"


/**
 * @brief Function to get the global public parameters (MPKE & MPKS of KGC), it checks if present in disk or if we need to retrieve it.
 * @param mpkSession The resulting MPKE
 * @param mpkSignature The resulting MPKS
 */
void getGlobalParams(encryption_mpk *mpkSession, signature_mpk *mpkSignature);

/**
 * @brief Function to get encrypted secrets value of an user.
 * @param userID The user to retrieve the params for
 * @param userPassword The user password to decrypt the data
 * @param salt The salt used at encryption (needed for save at the end of the program)
 * @param nonce The nonce used at encryption (needed for save at the end of the program)
 * @return A pointer to a binn object containing the secret values of a user and secret keys already generated.
 */
binn* getSecretsValue(char *userID, char *userPassword, unsigned char **salt, unsigned char **nonce);

/**
 * @brief Fuction to get public key of a certain user
 * @param encryptionPk The resulting Public key for encryption.
 * @param signaturePk The resulting public key for signature.
 * @param userID The desired userID to get for the PK.
 */
void getPk(encryption_pk *encryptionPk, signature_pk *signaturePk, char *userID);

void saveSecretsValue(binn *secrets, char *userID, char *userPassword, unsigned char **salt, unsigned char **nonce);

void getSecretKey(binn *secrets, char *timestamp, encryption_mpk mpkSession, signature_mpk mpkSignature, encryption_sk *encryptionSk, signature_sk *signatureSk, char *userID);

/**
 * @brief A small function to initiate a new connection to the KGC in order to ask something to it.
 * @return The socket to use
 */
int connectToKGC();

int sendmail(char* destination, char* source, char* subject, char* nonceAES, char* IDused, char* content, char* signature, char* cipher, char *email, char *password);
int checkmail(char *email, char *password);
binn* parseEmail(char* filename);
void displaySubject(char* filename);
#endif //POCCERTIFICATELESSCRYPTOGRAPHY_MAINCLIENT_H
