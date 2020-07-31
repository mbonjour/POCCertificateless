/**
 * @file socketUtils.c
 * @author Mickael Bonjour mickael.bonjour@heig-vd.ch
 * @date 13 juillet 2020
 * @brief This file gives a way to receive data from a socket with little chunks of data.
 */

#ifndef POCCERTIFICATELESSCRYPTOGRAPHY_SOCKETUTILS_H
#define POCCERTIFICATELESSCRYPTOGRAPHY_SOCKETUTILS_H

#include <sys/socket.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

/**
 * @brief Receives all data from a socket via a small chunk of data.
 * @param sock The socket we need to listen on to receive data
 * @param buf  Te buffer where
 * @return size of the received data
 */
size_t recvAll(int sock, unsigned char* buf, size_t size_buf);
#endif //POCCERTIFICATELESSCRYPTOGRAPHY_SOCKETUTILS_H
