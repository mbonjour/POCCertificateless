#include "socketUtils.h"

//Way to receive chunks of data, Taken from : https://stackoverflow.com/questions/10011098/how-to-receive-the-large-data-using-recv
size_t recvAll(int sock, unsigned char* buf, size_t size_buf){
    unsigned char buffer[512];  //temporary buffer
    unsigned char* temp_buf = buf;
    unsigned char* end_buf = buf + size_buf;
    size_t iByteCount;
    do {
        iByteCount = recv(sock, buffer,512,0);
        if ( iByteCount > 0 ) {
            //make sure we're not about to go over the end of the buffer
            if (!((temp_buf + iByteCount) <= end_buf))
                break;
            //fprintf(stderr, "Bytes received: %d\n",iByteCount);
            memcpy(temp_buf, buffer, iByteCount);
            temp_buf += iByteCount;
        }
        else if ( iByteCount == 0 ) {
            if(temp_buf != buf) {
                //do process with received data
            }
            else {
                fprintf(stderr, "receive failed");
                break;
            }
        }
        else {
            fprintf(stderr, "recv failed: ");
            break;
        }
    } while(iByteCount > 0 && temp_buf < end_buf);
    return iByteCount;
}