#include <sys/stat.h>
#include "mainClient.h"

#define PORT 10002
char *payload_text[12];
struct upload_status {
    int lines_read;
};
static void display_mailbox_list(struct mailimf_mailbox_list * mb_list, char *dest)
{
    clistiter * cur;

    for(cur = clist_begin(mb_list->mb_list) ; cur != NULL ;
        cur = clist_next(cur)) {
        struct mailimf_mailbox * mb;

        mb = clist_content(cur);

        //display_mailbox(mb);
        if (mb->mb_display_name != NULL) {
            strcat(dest, mb->mb_display_name);
            strcat(dest, " ");
        }
        //printf("<%s>", mb->mb_addr_spec);
        strcat(dest, mb->mb_addr_spec);
        if (clist_next(cur) != NULL) {
            strcat(dest, ", ");
        }
    }
}
static void display_address_list(struct mailimf_address_list * addr_list, char *dest)
{
    clistiter * cur;

    for(cur = clist_begin(addr_list->ad_list) ; cur != NULL ;
        cur = clist_next(cur)) {
        struct mailimf_address * addr;

        addr = clist_content(cur);

        switch (addr->ad_type) {
            case MAILIMF_ADDRESS_GROUP:
                strcat(dest, addr->ad_data.ad_group->grp_display_name);
                strcat(dest, ": ");
                clistiter * current;
                for(current = clist_begin(addr->ad_data.ad_group->grp_mb_list->mb_list) ; current != NULL ; current = clist_next(current)) {
                    struct mailimf_mailbox * mb;

                    mb = clist_content(current);
                    if (mb->mb_display_name != NULL) {
                        strcat(dest, mb->mb_display_name);
                        strcat(dest, " ");
                    }
                    //printf("<%s>", mb->mb_addr_spec);
                    strcat(dest, mb->mb_addr_spec);
                }
                strcat(dest, "; ");
                break;

            case MAILIMF_ADDRESS_MAILBOX:
                if (addr->ad_data.ad_mailbox->mb_display_name != NULL) {
                    strcat(dest, addr->ad_data.ad_mailbox->mb_display_name);
                    strcat(dest, " ");
                }
                //printf("<%s>", addr->ad_data.ad_mailbox->mb_addr_spec);
                strcat(dest, addr->ad_data.ad_mailbox->mb_addr_spec);
                break;
        }

        if (clist_next(cur) != NULL) {
            strcat(dest, ", ");
        }
    }
}

void displaySubject(char* filename){
    FILE *file;
    binn *mailReturn;
    mailReturn = binn_object();

    char* test = malloc(50);
    memset(test, 0, 50);
    strcat(test, "download/");
    strcat(test, filename);
    int r;
    struct mailmime * mime;
    struct stat stat_info;
    char * data;
    size_t current_index;

    file = fopen(test, "r");
    if (file == NULL) {
        exit(EXIT_FAILURE);
    }

    r = stat(test, &stat_info);
    if (r != 0) {
        fclose(file);
        exit(EXIT_FAILURE);
    }

    data = malloc(stat_info.st_size);
    fread(data, 1, stat_info.st_size, file);
    fclose(file);

    current_index = 0;
    r = mailmime_parse(data, stat_info.st_size,
                       &current_index, &mime);
    if (r != MAILIMF_NO_ERROR) {
        free(data);
        printf("Failed to pars\n");
        exit(EXIT_FAILURE);
    }
    // display_mime(mime);
    if (mime->mm_data.mm_message.mm_fields) {
        if (clist_begin(mime->mm_data.mm_message.mm_fields->fld_list) != NULL) {
            clistiter *cur;

            for (cur = clist_begin(mime->mm_data.mm_message.mm_fields->fld_list); cur != NULL;
                 cur = clist_next(cur)) {
                struct mailimf_field *f;

                f = clist_content(cur);
                if (f->fld_type == MAILIMF_FIELD_SUBJECT) {
                    printf("%s", f->fld_data.fld_subject->sbj_value);
                    break;
                }
            }
        }
    }
    mailmime_free(mime);
    free(data);
    free(test);
    binn_free(mailReturn);
}
binn* parseEmail(char* filename) {
    FILE *file;
    binn *mailReturn;
    mailReturn = binn_object();

    char *test = malloc(50);
    memset(test, 0, 50);
    strcat(test, "download/");
    strcat(test, filename);
    int r;
    struct mailmime *mime;
    struct stat stat_info;
    char *data;
    size_t current_index;

    file = fopen(test, "r");
    if (file == NULL) {
        exit(EXIT_FAILURE);
    }

    r = stat(test, &stat_info);
    if (r != 0) {
        fclose(file);
        exit(EXIT_FAILURE);
    }

    data = malloc(stat_info.st_size);
    fread(data, 1, stat_info.st_size, file);
    fclose(file);

    current_index = 0;
    r = mailmime_parse(data, stat_info.st_size,
                       &current_index, &mime);
    if (r != MAILIMF_NO_ERROR) {
        free(data);
        exit(EXIT_FAILURE);
        return EXIT_FAILURE;
    }

    // display_mime(mime);
    if (mime->mm_data.mm_message.mm_fields) {
        if (clist_begin(mime->mm_data.mm_message.mm_fields->fld_list) != NULL) {
            clistiter *cur;

            for (cur = clist_begin(mime->mm_data.mm_message.mm_fields->fld_list); cur != NULL;
                 cur = clist_next(cur)) {
                struct mailimf_field *f;

                f = clist_content(cur);
                switch (f->fld_type) {
                    case MAILIMF_FIELD_ORIG_DATE:
                        printf("\n");
                        char *dateFormat = malloc(50);
                        struct mailimf_date_time *d = f->fld_data.fld_orig_date->dt_date_time;
                        snprintf(dateFormat, 50, "%02i/%02i/%i %02i:%02i:%02i %+04i",
                                 d->dt_day, d->dt_month, d->dt_year,
                                 d->dt_hour, d->dt_min, d->dt_sec, d->dt_zone);
                        binn_object_set_str(mailReturn, "Date", dateFormat);
                        free(dateFormat);
                        break;
                    case MAILIMF_FIELD_FROM:
                        printf("\n");
                        char *fromList = malloc(256);
                        memset(fromList, 0, 256);
                        display_mailbox_list(f->fld_data.fld_from->frm_mb_list, fromList);
                        //printf("\n");
                        binn_object_set_str(mailReturn, "From", fromList);
                        free(fromList);
                        break;
                    case MAILIMF_FIELD_TO:
                        printf("\n");
                        char *toList = malloc(256);
                        memset(toList, 0, 256);
                        //display_to(f->fld_data.fld_to);
                        display_address_list(f->fld_data.fld_to->to_addr_list, toList);
                        //printf("\n");
                        binn_object_set_str(mailReturn, "To", toList);
                        free(toList);
                        break;
                    case MAILIMF_FIELD_CC:
                        printf("\n");
                        char *ccList = malloc(256);
                        memset(ccList, 0, 256);
                        //display_cc(f->fld_data.fld_cc);
                        display_address_list(f->fld_data.fld_cc->cc_addr_list, ccList);
                        //printf("\n");
                        binn_object_set_str(mailReturn, "CC", ccList);
                        free(ccList);
                        break;
                    case MAILIMF_FIELD_SUBJECT:
                        printf("\n");
                        //display_subject(f->fld_data.fld_subject);
                        binn_object_set_str(mailReturn, "Subject", f->fld_data.fld_subject->sbj_value);
                        //printf("\n");
                        break;
                    case MAILIMF_FIELD_MESSAGE_ID:
                        //printf("Message-ID: %s\n", f->fld_data.fld_message_id->mid_value);
                        binn_object_set_str(mailReturn, "Message-id", f->fld_data.fld_message_id->mid_value);
                        break;
                    case MAILIMF_FIELD_OPTIONAL_FIELD:
                        //printf("%s : %s\n",f->fld_data.fld_optional_field->fld_name, f->fld_data.fld_optional_field->fld_value);
                        binn_object_set_str(mailReturn, f->fld_data.fld_optional_field->fld_name,
                                            f->fld_data.fld_optional_field->fld_value);
                }
            }
        }
    }
    //printf("Body : %s", mime->mm_data.mm_message.mm_msg_mime->mm_body->dt_data.dt_filename);
    char *testCopy = malloc(mime->mm_data.mm_message.mm_msg_mime->mm_body->dt_data.dt_text.dt_length + 1);
    memcpy(testCopy, mime->mm_data.mm_message.mm_msg_mime->mm_body->dt_data.dt_text.dt_data,
           mime->mm_data.mm_message.mm_msg_mime->mm_body->dt_data.dt_text.dt_length);
    testCopy[mime->mm_data.mm_message.mm_msg_mime->mm_body->dt_data.dt_text.dt_length] = 0;
    binn_object_set_str(mailReturn, "Body", testCopy);
    mailmime_free(mime);
    free(data);
    free(test);
    free(testCopy);
    return mailReturn;
}

static size_t payload_source(void *ptr, size_t size, size_t nmemb, void *userp)
{
    struct upload_status *upload_ctx = (struct upload_status *)userp;
    const char *data;

    if((size == 0) || (nmemb == 0) || ((size*nmemb) < 1)) {
        return 0;
    }

    data = payload_text[upload_ctx->lines_read];

    if(data) {
        size_t len = strlen(data);
        memcpy(ptr, data, len);
        upload_ctx->lines_read++;

        return len;
    }

    return 0;
}

int sendmail(char* destination, char* source, char* subject, char* nonceAES, char* IDused, char* content, char* signature, char* cipher, char *email, char *password){

    char * to_text = malloc(100); // 52Kb for the moment
    memset(to_text, 0, 100);
    strcat(to_text, "To : ");
    strcat(to_text, destination);
    strcat(to_text, "\r\n");
    payload_text[0] = to_text;

    char * from_text = malloc(100); // 52Kb for the moment
    memset(from_text, 0, 100);
    strcat(from_text, "From : ");
    strcat(from_text, source);
    strcat(from_text, "\r\n");
    payload_text[1] = from_text;

    char * subject_text = malloc(100); // 52Kb for the moment
    memset(subject_text, 0, 100);
    strcat(subject_text, "Subject : ");
    strcat(subject_text, subject);
    strcat(subject_text, "\r\n");
    payload_text[2] = subject_text;

    char * aesNonce_text = malloc(100); // 52Kb for the moment
    memset(aesNonce_text, 0, 100);
    strcat(aesNonce_text, "X-AES-NONCE : ");
    strcat(aesNonce_text, nonceAES);
    strcat(aesNonce_text, "\r\n");
    payload_text[3] = aesNonce_text;

    char * fullID = malloc(100); // 52Kb for the moment
    memset(fullID, 0, 100);
    strcat(fullID, "X-TIMESTAMP-USED : ");
    strcat(fullID, IDused);
    strcat(fullID, "\r\n");
    payload_text[4] = fullID;

    char * signature_text = malloc(300); // 52Kb for the moment
    memset(signature_text, 0, 300);
    strcat(signature_text, "X-SIGNATURE-B64 : ");
    strcat(signature_text, signature);
    strcat(signature_text, "\r\n");
    payload_text[5] = signature_text;

    char * cipher_text = malloc(1000); // 52Kb for the moment
    memset(cipher_text, 0, 1000);
    strcat(cipher_text, "X-CIPHER-B64 : ");
    strcat(cipher_text, cipher);
    strcat(cipher_text, "\r\n");
    payload_text[6] = cipher_text;

    char * date_text = malloc(100);
    memset(date_text, 0, 100);
    strcat(date_text, "Date : ");
    char dateFormat[50] = {0};
    time_t t = time(NULL);
    struct tm *temp = localtime(&t);
    strftime(dateFormat, 50, "%02i/%02i/%i %02i:%02i:%02i %+04i", temp);
    strcat(date_text, dateFormat);
    strcat(date_text, "\r\n");
    payload_text[7] = date_text;

    char * before_body = malloc(50); // 52Kb for the moment
    memset(before_body, 0, 50);
    strcat(before_body, "\r\n");
    payload_text[8] = before_body;

    char * bodyEnd = malloc(10000); // 52Kb for the moment
    memset(bodyEnd, 0, 10000);
    strcat(bodyEnd, content);
    payload_text[9] = bodyEnd;

    char * nullTerminated = malloc(1); // 52Kb for the moment
    memset(nullTerminated, 0, 1);
    payload_text[10] = nullTerminated;

    CURL *curl;
    CURLcode res = CURLE_OK;
    struct curl_slist *recipients = NULL;
    struct upload_status upload_ctx;

    upload_ctx.lines_read = 0;

    curl = curl_easy_init();
    if(curl) {
        /* Set username and password */
        curl_easy_setopt(curl, CURLOPT_USERNAME, email);
        curl_easy_setopt(curl, CURLOPT_PASSWORD, password);

        /* This is the URL for your mailserver. Note the use of port 587 here,
         * instead of the normal SMTP port (25). Port 587 is commonly used for
         * secure mail submission (see RFC4403), but you should use whatever
         * matches your server configuration. */
        curl_easy_setopt(curl, CURLOPT_URL, "smtps://smtp.gmail.com:465");

        /* In this example, we'll start with a plain text connection, and upgrade
         * to Transport Layer Security (TLS) using the STARTTLS command. Be careful
         * of using CURLUSESSL_TRY here, because if TLS upgrade fails, the transfer
         * will continue anyway - see the security discussion in the libcurl
         * tutorial for more details. */
        curl_easy_setopt(curl, CURLOPT_USE_SSL, (long)CURLUSESSL_ALL);

        /* If your server doesn't have a valid certificate, then you can disable
         * part of the Transport Layer Security protection by setting the
         * CURLOPT_SSL_VERIFYPEER and CURLOPT_SSL_VERIFYHOST options to 0 (false).
         *   curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, 0L);
         *   curl_easy_setopt(curl, CURLOPT_SSL_VERIFYHOST, 0L);
         * That is, in general, a bad idea. It is still better than sending your
         * authentication details in plain text though.  Instead, you should get
         * the issuer certificate (or the host certificate if the certificate is
         * self-signed) and add it to the set of certificates that are known to
         * libcurl using CURLOPT_CAINFO and/or CURLOPT_CAPATH. See docs/SSLCERTS
         * for more information. */
        //curl_easy_setopt(curl, CURLOPT_CAINFO, "/path/to/certificate.pem");

        /* Note that this option isn't strictly required, omitting it will result
         * in libcurl sending the MAIL FROM command with empty sender data. All
         * autoresponses should have an empty reverse-path, and should be directed
         * to the address in the reverse-path which triggered them. Otherwise,
         * they could cause an endless loop. See RFC 5321 Section 4.5.5 for more
         * details.
         */
        curl_easy_setopt(curl, CURLOPT_MAIL_FROM, source);

        /* Add two recipients, in this particular case they correspond to the
         * To: and Cc: addressees in the header, but they could be any kind of
         * recipient. */
        recipients = curl_slist_append(recipients, destination);
        //recipients = curl_slist_append(recipients, CC);
        curl_easy_setopt(curl, CURLOPT_MAIL_RCPT, recipients);

        /* We're using a callback function to specify the payload (the headers and
         * body of the message). You could just use the CURLOPT_READDATA option to
         * specify a FILE pointer to read from. */
        curl_easy_setopt(curl, CURLOPT_READFUNCTION, payload_source);
        curl_easy_setopt(curl, CURLOPT_READDATA, &upload_ctx);
        curl_easy_setopt(curl, CURLOPT_UPLOAD, 1L);

        /* Since the traffic will be encrypted, it is very useful to turn on debug
         * information within libcurl to see what is happening during the transfer.
         */
        curl_easy_setopt(curl, CURLOPT_VERBOSE, 0L);

        /* Send the message */
        res = curl_easy_perform(curl);

        /* Check for errors */
        if(res != CURLE_OK)
            fprintf(stderr, "curl_easy_perform() failed: %s\n",
                    curl_easy_strerror(res));

        /* Free the list of recipients */
        curl_slist_free_all(recipients);

        /* Always cleanup */
        curl_easy_cleanup(curl);
    }
    free(nullTerminated);
    free(bodyEnd);
    free(before_body);
    free(cipher_text);
    free(signature_text);free(fullID);
    free(aesNonce_text);
    free(subject_text);
    free(from_text);
    free(to_text);

    return (int)res;
}
static void check_error(int r, char * msg)
{
    if (r == MAILIMAP_NO_ERROR)
        return;
    if (r == MAILIMAP_NO_ERROR_AUTHENTICATED)
        return;
    if (r == MAILIMAP_NO_ERROR_NON_AUTHENTICATED)
        return;

    fprintf(stderr, "%s\n", msg);
    exit(EXIT_FAILURE);
}

static char * get_msg_att_msg_content(struct mailimap_msg_att * msg_att, size_t * p_msg_size)
{
    clistiter * cur;

    /* iterate on each result of one given message */
    for(cur = clist_begin(msg_att->att_list) ; cur != NULL ; cur = clist_next(cur)) {
        struct mailimap_msg_att_item * item;

        item = clist_content(cur);
        if (item->att_type != MAILIMAP_MSG_ATT_ITEM_STATIC) {
            continue;
        }

        if (item->att_data.att_static->att_type != MAILIMAP_MSG_ATT_BODY_SECTION) {
            continue;
        }

        * p_msg_size = item->att_data.att_static->att_data.att_body_section->sec_length;
        return item->att_data.att_static->att_data.att_body_section->sec_body_part;
    }

    return NULL;
}

static char * get_msg_content(clist * fetch_result, size_t * p_msg_size)
{
    clistiter * cur;

    /* for each message (there will probably be only one message) */
    for(cur = clist_begin(fetch_result) ; cur != NULL ; cur = clist_next(cur)) {
        struct mailimap_msg_att * msg_att;
        size_t msg_size;
        char * msg_content;

        msg_att = clist_content(cur);
        msg_content = get_msg_att_msg_content(msg_att, &msg_size);
        if (msg_content == NULL) {
            continue;
        }

        * p_msg_size = msg_size;
        return msg_content;
    }

    return NULL;
}

static void fetch_msg(struct mailimap * imap, uint32_t uid)
{
    struct mailimap_set * set;
    struct mailimap_section * section;
    char filename[512];
    size_t msg_len;
    char * msg_content;
    FILE * f;
    struct mailimap_fetch_type * fetch_type;
    struct mailimap_fetch_att * fetch_att;
    int r;
    clist * fetch_result;
    struct stat stat_info;

    snprintf(filename, sizeof(filename), "download/%u.eml", (unsigned int) uid);
    r = stat(filename, &stat_info);
    if (r == 0) {
        // already cached
        //printf("%u is already fetched\n", (unsigned int) uid);
        return;
    }

    set = mailimap_set_new_single(uid);
    fetch_type = mailimap_fetch_type_new_fetch_att_list_empty();
    section = mailimap_section_new(NULL);
    fetch_att = mailimap_fetch_att_new_body_peek_section(section);
    mailimap_fetch_type_new_fetch_att_list_add(fetch_type, fetch_att);

    r = mailimap_uid_fetch(imap, set, fetch_type, &fetch_result);
    check_error(r, "could not fetch");
    printf("fetch %u\n", (unsigned int) uid);

    msg_content = get_msg_content(fetch_result, &msg_len);
    if (msg_content == NULL) {
        fprintf(stderr, "no content\n");
        mailimap_fetch_list_free(fetch_result);
        return;
    }

    f = fopen(filename, "w");
    if (f == NULL) {
        fprintf(stderr, "could not write\n");
        mailimap_fetch_list_free(fetch_result);
        return;
    }

    fwrite(msg_content, 1, msg_len, f);
    fclose(f);

    //printf("%u has been fetched\n", (unsigned int) uid);

    mailimap_fetch_list_free(fetch_result);
    mailimap_fetch_type_free(fetch_type);
    mailimap_set_free(set);
}

static uint32_t get_uid(struct mailimap_msg_att * msg_att)
{
    clistiter * cur;

    /* iterate on each result of one given message */
    for(cur = clist_begin(msg_att->att_list) ; cur != NULL ; cur = clist_next(cur)) {
        struct mailimap_msg_att_item * item;

        item = clist_content(cur);
        if (item->att_type != MAILIMAP_MSG_ATT_ITEM_STATIC) {
            continue;
        }

        if (item->att_data.att_static->att_type != MAILIMAP_MSG_ATT_UID) {
            continue;
        }

        return item->att_data.att_static->att_data.att_uid;
    }

    return 0;
}

static void fetch_messages(struct mailimap * imap)
{
    struct mailimap_set * set;
    struct mailimap_fetch_type * fetch_type;
    struct mailimap_fetch_att * fetch_att;
    clist * fetch_result;
    clistiter * cur;
    int r;
    time_t rawtime = time(NULL);
    rawtime -= 86400;
    struct tm *ptm = localtime(&rawtime);
    struct mailimap_date *dateSince = mailimap_date_new(ptm->tm_mday, ptm->tm_mon + 1, ptm->tm_year + 1900);
    struct mailimap_search_key *keySince = mailimap_search_key_new_since(dateSince);
    clist* testResult;
    r = mailimap_search(imap, NULL, keySince, &testResult);
    check_error(r, "Could not compute last emails");
    mailimap_search_key_free(keySince);

    fetch_type = mailimap_fetch_type_new_fetch_att_list_empty();
    fetch_att = mailimap_fetch_att_new_uid();
    mailimap_fetch_type_new_fetch_att_list_add(fetch_type, fetch_att);

    set = mailimap_set_new(testResult);
    //mailimap_fetch_list_free(testResult);

    r = mailimap_fetch(imap, set, fetch_type, &fetch_result);
    check_error(r, "could not fetch");

    /* for each message */
    for(cur = clist_begin(fetch_result) ; cur != NULL ; cur = clist_next(cur)) {
        struct mailimap_msg_att * msg_att;
        uint32_t uid;

        msg_att = clist_content(cur);
        uid = get_uid(msg_att);
        if (uid == 0)
            continue;

        fetch_msg(imap, uid);
    }
    mailimap_set_free(set);

    mailimap_fetch_list_free(fetch_result);

    mailimap_fetch_type_free(fetch_type);
}
int checkmail(char* email, char *password){
    struct mailimap * imap;
    int r;

    mkdir("download", 0700);

    imap = mailimap_new(0, NULL);
    r = mailimap_ssl_connect(imap, "imap.gmail.com", 993);
    fprintf(stderr, "connect: %i\n", r);
    check_error(r, "could not connect to server");

    r = mailimap_login(imap, email, password);
    check_error(r, "could not login");

    r = mailimap_select(imap, "INBOX");
    check_error(r, "could not select INBOX");

    fetch_messages(imap);

    mailimap_logout(imap);
    mailimap_free(imap);
}


void getGlobalParams(encryption_mpk *mpkSession, signature_mpk *mpkSignature){
    FILE *file;
    file = fopen("globalMPK", "r");
    if (file){
        int r;
        struct stat stat_info;
        r = stat("globalMPK", &stat_info);
        if (r != 0) {
            fclose(file);
            exit(EXIT_FAILURE);
        }

        char * data = malloc(stat_info.st_size);
        fread(data, 1, stat_info.st_size, file);
        fclose(file);
        binn *savedMPK;
        savedMPK = binn_open(data);

        binn *obj;
        obj = binn_list_object(savedMPK, 1);
        deserialize_MPKE(obj, mpkSession);

        obj = binn_list_object(savedMPK, 2);
        deserialize_MPKS(obj, mpkSignature);
        free(data);
        binn_free(savedMPK);
        return;
    }
    file = fopen("globalMPK", "w");
    int sock = connectToKGC();

    binn *objToSend;
    objToSend = binn_object();
    binn_object_set_str(objToSend, "opCode", "HELO");
    binn_object_set_str(objToSend, "ID", "Get-MPK");
    send(sock , binn_ptr(objToSend) , binn_size(objToSend) , 0 );
    binn_free(objToSend);
    printf("Retrieving all public params from KGC\n");

    unsigned char buf[52000];  //52Kb fixed-size buffer
    recvAll(sock, buf, 52000);

    binn *listReceived;
    listReceived = binn_open(buf);
    binn *mpks, *mpke;
    mpks = binn_list_object(listReceived, 1);
    mpke = binn_list_object(listReceived, 2);
    deserialize_MPKS(mpks, mpkSignature);
    deserialize_MPKE(mpke, mpkSession);
    binn_free(listReceived);

    binn* list;
    list = binn_list();
    binn *obj;
    obj = binn_object();
    serialize_MPKE(obj, *mpkSession);
    binn_list_add_object(list, obj);
    binn_free(obj);

    obj = binn_object();
    serialize_MPKS(obj, *mpkSignature);
    binn_list_add_object(list, obj);
    binn_free(obj);
    fwrite(binn_ptr(list), binn_size(list), 1, file);
    fclose(file);
    binn_free(list);
}

binn* getSecretsValue(char *userID, char *userPassword, unsigned char **salt, unsigned char **nonce) {
    FILE *file;
    char *secretFile = malloc(330);
    memset(secretFile, 0, 330);
    strcpy(secretFile, userID);
    strcat(secretFile, "_SK");

    file = fopen(secretFile, "r");
    if (file){
        printf("Please give us the password to decrypt your personal data : \n");
        // Max size of an email address
        //userPassword = malloc(320);
        fgets(userPassword, 320, stdin);
        userPassword[strlen(userPassword)-1] = '\x00';
        unsigned char aesk[crypto_secretbox_KEYBYTES];
        int r;
        struct stat stat_info;
        r = stat(secretFile, &stat_info);
        if (r != 0) {
            fclose(file);
            exit(EXIT_FAILURE);
        }

        char * data = malloc(stat_info.st_size);
        fread(data, 1, stat_info.st_size, file);
        fclose(file);

        size_t saltSize;
        binn *objParams;
        objParams = binn_open(data);
        char *saltSaved = binn_object_str(objParams, "salt");
        *salt = base64_decode(saltSaved, strlen(saltSaved), &saltSize);

        size_t outLen;
        char *encryptedParams = binn_object_str(objParams, "b64Encrypted");
        unsigned char *decodedParams = base64_decode(encryptedParams, strlen(encryptedParams), &outLen);

        size_t outLenNonce;
        char *nonceB64 = binn_object_str(objParams, "nonce");
        *nonce = base64_decode(nonceB64, strlen(nonceB64), &outLenNonce);

        if (crypto_pwhash
                    (aesk, sizeof aesk, userPassword, strlen(userPassword), *salt,
                     crypto_pwhash_OPSLIMIT_INTERACTIVE, crypto_pwhash_MEMLIMIT_INTERACTIVE,
                     crypto_pwhash_ALG_DEFAULT) != 0) {
            printf("Not enough memory");
            /* out of memory */
        }

        char *decryptedParams = malloc(outLen);
        decrypt_message(decryptedParams, decodedParams, *nonce, aesk, outLen, NULL,0);
        //free(nonceDecoded);
        free(decodedParams);
        //free(userPassword);
        //free(salt);
        binn_free(objParams);
        free(data);

        binn *savedSecrets;
        savedSecrets = binn_open(decryptedParams);
        free(secretFile);

        binn_iter iter;
        binn *savedSecCopy;
        char key[256];
        binn value;
        savedSecCopy = binn_object();
        binn_object_foreach(savedSecrets, key, value){
            void *copySec;
            if(strcmp(key, "encryption_secret") == 0){
                copySec = malloc(value.size);
                memcpy(copySec, value.ptr, value.size);
                binn_object_set_blob(savedSecCopy, key, copySec, value.size);
            }
            else if(strcmp(key, "signature_secret") == 0){
                copySec = malloc(value.size);
                memcpy(copySec, value.ptr, value.size);
                binn_object_set_blob(savedSecCopy, key, copySec, value.size);

            } else {
                copySec = malloc(value.size);
                memcpy(copySec, value.ptr, value.size);
                binn_object_set_object(savedSecCopy, key, copySec);
            }
            free(copySec);
        }
        free(decryptedParams);
        binn_free(savedSecrets);

        return savedSecCopy;
    }

    printf("Generating and saving secret values and public keys\n");
    // Now we can go for user's private keys (encrypting and signing)
    bn_t encryption_secret;
    bn_t signature_secret;

    setSec(&encryption_secret);
    setSecSig(&signature_secret);

    binn *obj;
    obj = binn_object();
    int size = bn_size_bin(encryption_secret);
    uint8_t *bin = malloc(size);
    bn_write_bin(bin, size, encryption_secret);
    binn_object_set_blob(obj, "encryption_secret", bin, size);
    //binn_free(obj);
    free(bin);

    //obj = binn_object();
    size = bn_size_bin(signature_secret);
    bin = malloc(size);
    bn_write_bin(bin, size, signature_secret);
    binn_object_set_blob(obj,"signature_secret", bin, size);
    //binn_free(obj);
    free(bin);

    // Now we can go to set Public keys for both signing and encrypting

    encryption_mpk mpkSession;
    signature_mpk mpkSignature;
    getGlobalParams(&mpkSession, &mpkSignature);

    encryption_pk encryptionPk;
    signature_pk signaturePk;

    setPub(encryption_secret, mpkSession, &encryptionPk);
    setPubSig(signature_secret, mpkSignature, &signaturePk);

    int sock = connectToKGC();

    binn* pkBinnObj;
    pkBinnObj = binn_list();
    binn* encryption_PkBinnObj, *signature_PkBinnObj;
    encryption_PkBinnObj = binn_object();
    signature_PkBinnObj = binn_object();
    serialize_PKE(encryption_PkBinnObj, encryptionPk);
    serialize_PKS(signature_PkBinnObj, signaturePk);
    binn_list_add_object(pkBinnObj, encryption_PkBinnObj);
    binn_list_add_object(pkBinnObj, signature_PkBinnObj);
    binn_free(encryption_PkBinnObj);
    binn_free(signature_PkBinnObj);

    binn* packetSendingPK;
    packetSendingPK = binn_object();
    binn_object_set_str(packetSendingPK, "opCode", "PK");
    binn_object_set_str(packetSendingPK, "ID", userID);

    size_t outLen;
    unsigned char* b64Payload = base64_encode(binn_ptr(pkBinnObj), binn_size(pkBinnObj), &outLen);
    FILE *pkFile;
    char *pkFilename = malloc(330);
    memset(pkFilename, 0, 330);
    strcpy(pkFilename, userID);
    strcat(pkFilename, "_PK");

    pkFile = fopen(pkFilename, "w");
    fwrite(binn_ptr(pkBinnObj), binn_size(pkBinnObj), 1, pkFile);
    fclose(pkFile);
    free(pkFilename);

    //printf("PK obj : %s\n", b64Payload);
    binn_object_set_str(packetSendingPK, "PK", b64Payload);
    free(b64Payload);

    int sizeSent = send(sock, binn_ptr(packetSendingPK), binn_size(packetSendingPK), 0);
    //printf("Size of PK : %d\n", sizeSent);
    binn_free(pkBinnObj);
    binn_free(packetSendingPK);
    printf("In order to securely save your personal parameters we need you to provide a (strong) password for encrypting your personal data : \n");
    // Max size of an email address
    // userPassword = malloc(320);
    fgets(userPassword, 320, stdin);
    userPassword[strlen(userPassword)-1] = '\x00';
    free(secretFile);
    return obj;
}

void saveSecretsValue(binn *secrets, char *userID, char *userPassword, unsigned char **salt, unsigned char **nonce) {
    FILE *savingParams;
    char *secretFile = malloc(330);
    memset(secretFile, 0, 330);
    strcpy(secretFile, userID);
    strcat(secretFile, "_SK");
    savingParams = fopen(secretFile, "wb");
    if (*salt == NULL || *nonce == NULL){
        *salt = malloc(crypto_pwhash_SALTBYTES);
        //printf("We give the salt and need to store it for future use :\n");
        randombytes_buf(*salt, crypto_pwhash_SALTBYTES);
        *nonce = malloc(crypto_aead_aes256gcm_NPUBBYTES);
        randombytes_buf(*nonce, crypto_aead_aes256gcm_NPUBBYTES);
    }
    if(savingParams) {
        size_t outLen;
        unsigned char *m = binn_ptr(secrets);
        unsigned long m_len = binn_size(secrets);
        unsigned char aesk[crypto_secretbox_KEYBYTES];

        size_t sizeB64Salt;
        unsigned char *b64Salt = base64_encode(*salt, crypto_pwhash_SALTBYTES, &sizeB64Salt);
        //printf("%s\n", b64Salt);

        if (crypto_pwhash
                    (aesk, sizeof aesk, userPassword, strlen(userPassword), *salt,
                     crypto_pwhash_OPSLIMIT_INTERACTIVE, crypto_pwhash_MEMLIMIT_INTERACTIVE,
                     crypto_pwhash_ALG_DEFAULT) != 0) {
            printf("Not enough memory");
            /* out of memory */
        }

        unsigned long long cipher_len;
        unsigned char ciphertextAES[m_len + crypto_aead_aes256gcm_ABYTES];
        encrypt_message(m, aesk, *nonce, ciphertextAES, &cipher_len, &m_len, NULL, 0);
        //printf("We give the nonce and need to store it for future use :\n");
        size_t outLenB64Nonce;
        unsigned char *b64nonce = base64_encode(*nonce, crypto_aead_aes256gcm_NPUBBYTES, &outLenB64Nonce);
        //printf("%s\n", b64nonce);

        size_t b64EncryptedLen;
        unsigned char *encryptedContent = base64_encode(ciphertextAES, cipher_len, &b64EncryptedLen);
        binn *savedParamsBinn;
        savedParamsBinn = binn_object();
        binn_object_set_str(savedParamsBinn, "b64Encrypted", encryptedContent);
        binn_object_set_str(savedParamsBinn, "nonce", b64nonce);
        binn_object_set_str(savedParamsBinn, "salt", b64Salt);
        size_t test = fwrite(binn_ptr(savedParamsBinn), binn_size(savedParamsBinn), 1, savingParams);
        if(test > 0){
            printf("Encypted params saved\n");
        } else {
            printf("Failed to save Params\n");
        }
        free(b64nonce);
        free(b64Salt);
        //free(userPassword);
        free(encryptedContent);
        fclose(savingParams);
        binn_free(savedParamsBinn);
    } else {
        printf("Failed to open a file to save params\n");
    }
    free(secretFile);
}

void getPk(encryption_pk *encryptionPk, signature_pk *signaturePk, char *userID){
    FILE *file;
    char *pkFile = malloc(330);
    memset(pkFile, 0, 330);
    strcpy(pkFile, userID);
    strcat(pkFile, "_PK");
    file = fopen(pkFile, "rb");
    if (file){
        int r;
        struct stat stat_info;
        r = stat(pkFile, &stat_info);
        if (r != 0) {
            fclose(file);
            exit(EXIT_FAILURE);
        }

        char * data = malloc(stat_info.st_size);
        fread(data, 1, stat_info.st_size, file);
        fclose(file);

        binn *testObj;
        testObj = binn_open(data);
        binn *binEncryptionPk, *binSignaturePk;
        binEncryptionPk = binn_list_object(testObj, 1);
        binSignaturePk = binn_list_object(testObj, 2);
        deserialize_PKE(binEncryptionPk, encryptionPk);
        deserialize_PKS(binSignaturePk, signaturePk);
        binn_free(testObj);
        free(data);
        free(pkFile);
        return;
    }
    binn *objSavedPk;
    objSavedPk = binn_list();

    int sock = connectToKGC();
    binn *getPKBinnObj;
    getPKBinnObj = binn_object();
    binn_object_set_str(getPKBinnObj, "opCode", "GPE");
    binn_object_set_str(getPKBinnObj, "ID", userID);
    send(sock, binn_ptr(getPKBinnObj), binn_size(getPKBinnObj), 0);
    binn_free(getPKBinnObj);

    char bufferGPE[512] = {0};
    int testSize = recv(sock, bufferGPE, 512, 0);
    // printf("%s\n", bufferGPE);
    binn *retrivedPKE;
    retrivedPKE = binn_open(bufferGPE);
    char *error = binn_object_str(retrivedPKE, "Error");
    if(error != NULL) {
        printf("Error server : %s", error);
        exit(EXIT_FAILURE);
    }
    int size_PKE;
    void *bufferGPE2 = binn_object_blob(retrivedPKE, "PKE", &size_PKE);

    size_t out_len_test;
    unsigned char *decodedTest = base64_decode(bufferGPE2, testSize, &out_len_test);
    //binn_object_set_blob(objSavedPk, "encryption_pk", decodedTest, out_len_test);

    deserialize_PKE(decodedTest, encryptionPk);
    free(decodedTest);

    sock = connectToKGC();
    binn *getPKSBinnObj;
    getPKSBinnObj = binn_object();
    binn_object_set_str(getPKSBinnObj, "opCode", "GPS");
    binn_object_set_str(getPKSBinnObj, "ID", userID);
    send(sock, binn_ptr(getPKSBinnObj), binn_size(getPKSBinnObj), 0);
    binn_free(getPKSBinnObj);

    char bufferGPS[512] = {0};
    int testSizeGPS = recv(sock, bufferGPS, 512, 0);
    binn *retrivedPK;
    retrivedPK = binn_open(bufferGPS);
    char *errorPKS = binn_object_str(retrivedPK, "Error");
    if(error == NULL) {
        printf("Error server : %s", errorPKS);
        exit(EXIT_FAILURE);
    }
    int size_PKS;
    void *bufferGPS2 = binn_object_blob(retrivedPK, "PKS", &size_PKS);
    // printf("%s\n", bufferGPE);
    size_t out_len_test_gps;
    unsigned char *signature_sourcePKBin = base64_decode(bufferGPS2, testSizeGPS, &out_len_test_gps);
    //binn_object_set_blob(objSavedPk, "signature_pk", signature_sourcePKBin, out_len_test_gps);
    deserialize_PKS(signature_sourcePKBin, signaturePk);
    free(signature_sourcePKBin);
    file = fopen(pkFile, "wb");
    binn* encryption_PkBinnObj, *signature_PkBinnObj;
    encryption_PkBinnObj = binn_object();
    signature_PkBinnObj = binn_object();
    serialize_PKE(encryption_PkBinnObj, *encryptionPk);
    serialize_PKS(signature_PkBinnObj, *signaturePk);
    binn_list_add_object(objSavedPk, encryption_PkBinnObj);
    binn_list_add_object(objSavedPk, signature_PkBinnObj);
    binn_free(encryption_PkBinnObj);
    binn_free(signature_PkBinnObj);
    fwrite(binn_ptr(objSavedPk), binn_size(objSavedPk), 1, file);
    fclose(file);
    binn_free(objSavedPk);
    free(pkFile);
}

int connectToKGC(){
    int sock = 0;
    struct sockaddr_in serv_addr;

    if ((sock = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
        printf("\n Socket creation error \n");
        return -1;
    }
    serv_addr.sin_family = AF_INET;
    serv_addr.sin_port = htons(PORT);
    // Convert IPv4 and IPv6 addresses from text to binary form
    if(inet_pton(AF_INET, "127.0.0.1", &serv_addr.sin_addr)<=0) {
        printf("\nInvalid address/ Address not supported \n");
        return -1;
    }
    if (connect(sock, (struct sockaddr *)&serv_addr, sizeof(serv_addr)) < 0)
    {
        printf("\nConnection Failed \n");
        exit(EXIT_FAILURE);
    }
    return sock;
}

void getSecretKey(binn *secrets, char *timestamp, encryption_mpk mpkSession, signature_mpk mpkSignature,encryption_sk *encryptionSk, signature_sk *signatureSk, char *userID){
    char *fullID = malloc(330);
    memset(fullID, 0, 330);
    strcpy(fullID, userID);
    if(strcmp(timestamp, "default") != 0) {
        strcat(fullID, "+");
        strcat(fullID, timestamp);
    }
    binn *currentSK;
    currentSK = binn_object_object(secrets, timestamp);
    if (currentSK == NULL) {

        bn_t encryption_secret;
        bn_null(encryption_secret)
        bn_new(encryption_secret)

        bn_t signature_secret;
        bn_null(signature_secret)
        bn_new(signature_secret)

        void *binEncryptionVal, *binSignatureVal;
        int binEncryptionValLen, binSignatureValLen;
        binEncryptionVal = binn_object_blob(secrets, "encryption_secret", &binEncryptionValLen);
        binSignatureVal = binn_object_blob(secrets, "signature_secret", &binSignatureValLen);
        bn_read_bin(encryption_secret, binEncryptionVal, binEncryptionValLen);
        bn_read_bin(signature_secret, binSignatureVal, binSignatureValLen);

        signature_ppk signature_senderPpk;
        int sock = connectToKGC();
        char bufferPPK[1024] = {0};
        binn *signatureExtractionSenderBinnObj;
        signatureExtractionSenderBinnObj = binn_object();
        binn_object_set_str(signatureExtractionSenderBinnObj, "opCode", "SE");
        binn_object_set_str(signatureExtractionSenderBinnObj, "ID", fullID);
        send(sock, binn_ptr(signatureExtractionSenderBinnObj), binn_size(signatureExtractionSenderBinnObj), 0);
        binn_free(signatureExtractionSenderBinnObj);

        read(sock, bufferPPK, 1024);
        deserialize_PPKS(bufferPPK, &signature_senderPpk);
        setPrivSig(signature_secret, signature_senderPpk, mpkSignature, fullID, signatureSk);

        encryption_ppk PartialKeysBob;

        sock = connectToKGC();

        char bufferPPKE[1024] = {0};
        binn* bobPpk;
        bobPpk = binn_object();
        binn_object_set_str(bobPpk, "opCode", "EE");
        binn_object_set_str(bobPpk, "ID", fullID);
        send(sock, binn_ptr(bobPpk), binn_size(bobPpk), 0);
        binn_free(bobPpk);

        read(sock, bufferPPKE, 1024);
        deserialize_PPKE(bufferPPKE, &PartialKeysBob);

        // Computes Secret User Keys
        g2_null(encryptionSk->s1)
        g2_new(encryptionSk->s1)

        g1_null(encryptionSk->s2)
        g1_new(encryptionSk->s2)
        setPriv(encryption_secret, PartialKeysBob, mpkSession, fullID, encryptionSk);

        binn *addSK;
        addSK = binn_object();
        binn *addSKE;
        addSKE = binn_object();
        binn *addSKS;
        addSKS = binn_object();

        serialize_SKE(addSKE, *encryptionSk);
        binn_object_set_object(addSK, "encryption_sk", addSKE);
        serialize_SKS(addSKS, *signatureSk);
        binn_object_set_object(addSK, "signature_sk", addSKS);

        binn_object_set_object(secrets, timestamp, addSK);
        binn_free(addSK);
        binn_free(addSKE);
        binn_free(addSKS);
    } else {
        binn *objSKE;
        binn *objSKS;
        objSKE = binn_object_object(currentSK, "encryption_sk");
        objSKS = binn_object_object(currentSK, "signature_sk");
        deserialize_SKE(objSKE, encryptionSk);
        deserialize_SKS(objSKS, signatureSk);
    }
    free(fullID);
}

int main() {
    if(core_init() == RLC_ERR){
        printf("RELIC INIT ERROR !\n");
    }
    if(sodium_init() < 0) {
        printf("LIBSODIUM INIT ERROR !\n");
    }
    if(pc_param_set_any() == RLC_OK){
        pc_param_print();
        //printf("Security : %d\n", pc_param_level());

        // MPK struct, Master Public Key structure to store
        encryption_mpk mpkSession;
        signature_mpk mpkSignature;
        getGlobalParams(&mpkSession, &mpkSignature);

        bn_t encryption_secret;
        bn_null(encryption_secret)
        bn_new(encryption_secret)

        bn_t signature_secret;
        bn_null(signature_secret)
        bn_new(signature_secret)

        encryption_pk encryptionPk;
        signature_pk signaturePk;

        // Max size of an email address
        char* userID = malloc(320);
        printf("What's your email (Gmail) ?\n");
        fgets(userID, 320, stdin);
        userID[strlen(userID)-1] = '\x00';

        // Max size of an email address
        char* password = malloc(320);
        printf("What's your password (Gmail) ?\n");
        fgets(password, 320, stdin);
        password[strlen(password)-1] = '\x00';

        char *userPassword = malloc(320);
        unsigned char *salt = NULL;
        unsigned char *nonce = NULL;
        binn *secrets = getSecretsValue(userID, userPassword, &salt, &nonce);
        getPk(&encryptionPk, &signaturePk, userID);

        void *binEncryptionVal, *binSignatureVal;
        int binEncryptionValLen, binSignatureValLen;
        binEncryptionVal = binn_object_blob(secrets, "encryption_secret", &binEncryptionValLen);
        binSignatureVal = binn_object_blob(secrets, "signature_secret", &binSignatureValLen);
        bn_read_bin(encryption_secret, binEncryptionVal, binEncryptionValLen);
        bn_read_bin(signature_secret, binSignatureVal, binSignatureValLen);

        printf("Do you want to send an email (0) or decrypt one (1) ?\n");
        int sendOrDecryptUser;
        char* charUserChoice = malloc(4);
        fgets(charUserChoice, 4, stdin);
        charUserChoice[strlen(charUserChoice)-1] = '\x00';

        sendOrDecryptUser = strtol(charUserChoice, NULL, 10);
        // If we want to send an email
        if(sendOrDecryptUser == 0) {
            // At this point we're sure that params are full, by generating them or retrieving from the user disk
            // So now we can ask the user about the email he want to send
            printf("Please enter the destination address of the email :\n");
            char *destinationID = malloc(320);
            fgets(destinationID, 320, stdin);
            destinationID[strlen(destinationID)-1] = '\x00';

            // Max size seems to be like more than 130 chars but some email clients truncate to 130
            printf("What's the subject :\n");
            char *subject = malloc(130);
            fgets(subject, 130, stdin);
            subject[strlen(subject)-1] = '\x00';

            printf("Message :\n");
            //arbitrary size
            char *message = malloc(10000);
            fgets(message, 10000, stdin);
            message[strlen(message)-1] = '\x00';
            printf("\n\nHere is a summary of the mail that will be sent, are you ok (yes/no) ?\n");
            printf("From : %s\n", userID);
            printf("To : %s\n", destinationID);
            printf("Subject : %s\n", subject);
            printf("Content : %s\n", message);

            char *userChoice = malloc(4);
            fgets(userChoice, 4, stdin);
            userChoice[strlen(userChoice)-1] = '\x00';
            if (strcmp(userChoice, "no") == 0) {
                printf("Not implemented yet");
                return -1;
            }
            free(userChoice);

            encryption_pk destPKE;
            signature_pk destPKS;
            getPk(&destPKE, &destPKS, destinationID);
            //TODO : do this for all destination, or implement something on te KGC to send all the asked public keys

            // The other user takes ID of the destination and PK to encrypt his message
            // With the final version we will need to append a timestamp on the ID

            gt_t AESK;gt_null(AESK);gt_new(AESK);
            // For now we take m (AES Key) randomly from Gt
            gt_rand(AESK);

            unsigned char aesk[crypto_secretbox_KEYBYTES];
            get_key(aesk, AESK);

            unsigned char nonceAES[crypto_aead_aes256gcm_NPUBBYTES];
            size_t m_len = strlen(message);
            unsigned long long cipher_len;
            unsigned char ciphertextAES[m_len + crypto_aead_aes256gcm_ABYTES];
            size_t authenticatedDataSize = strlen(userID) + strlen(destinationID) + strlen(subject) + 1;
            unsigned char *authenticatedData = malloc(authenticatedDataSize);
            memset(authenticatedData, 0, authenticatedDataSize);
            strcpy(authenticatedData, userID);
            strcat(authenticatedData, destinationID);
            strcat(authenticatedData, subject);
            encrypt_message(message, aesk, nonceAES, ciphertextAES, &cipher_len, &m_len, authenticatedData, authenticatedDataSize);
            size_t ciphertextLen;
            unsigned char *ciphertextB64 = base64_encode(ciphertextAES, cipher_len, &ciphertextLen);
            //printf("Encrypted message : %s\n", ciphertextB64);

            unsigned char *nonceAesB64 = base64_encode(nonceAES, crypto_aead_aes256gcm_NPUBBYTES, NULL);
            //printf("Nonce message : %s\n", nonceAesB64);

            // Encryption of the AES Key with the Public key of the destination
            cipher c;
            char *destinationTimestamp = malloc(330);
            memset(destinationTimestamp, 0, 330);
            strcpy(destinationTimestamp, destinationID);
            strcat(destinationTimestamp, "+");
            time_t timestampNow = time(NULL);
            timestampNow -= timestampNow % 604800;
            char *timestampStr = malloc(20);
            memset(timestampStr, 0, 20);
            sprintf(timestampStr, "%d", timestampNow);

            strcat(destinationTimestamp, timestampStr);

            encrypt(AESK, destPKE, destinationTimestamp, mpkSession, &c);
            binn *cipherBinnObect;
            cipherBinnObect = binn_object();
            serialize_Cipher(cipherBinnObect, c);
            unsigned char *cipherB64 = base64_encode(binn_ptr(cipherBinnObect), binn_size(cipherBinnObect), NULL);
            //printf("Cipher base64 : %s\n", cipherB64);

            binn_free(cipherBinnObect);

            // For the signature we need our PPK

            // Computes Secret User Keys for Signature
            signature_sk signature_senderSk;
            encryption_sk encryption_senderSk;
            getSecretKey(secrets, "default", mpkSession, mpkSignature, &encryption_senderSk, &signature_senderSk, userID);

            // Computes the message to sign, so the cipher struct
            int c0size = gt_size_bin(c.c0, 1);
            int c1Size = g1_size_bin(c.c1, 1);
            int c2Size = g2_size_bin(c.c2, 1);
            int c3Size = g2_size_bin(c.c3, 1);
            uint8_t mSig[c0size + c1Size + c2Size + c3Size + ciphertextLen];
            gt_write_bin(mSig, c0size, c.c0, 1);
            g1_write_bin(&mSig[c0size], c1Size, c.c1, 1);
            g2_write_bin(&mSig[c0size + c1Size], c2Size, c.c2, 1);
            g2_write_bin(&mSig[c0size + c1Size + c2Size], c3Size, c.c3, 1);
            memcpy(&mSig[c0size + c1Size + c2Size + c3Size], ciphertextB64, ciphertextLen);

            // Structure of an signature
            signature s;
            // We can sign using our private keys and public ones
            sign(mSig, signature_senderSk, signaturePk, userID, mpkSignature, &s);
            binn *signatureObjBinn;
            signatureObjBinn = binn_object();
            serialize_Signature(signatureObjBinn, s);
            unsigned char *b64signatureObjBinn = base64_encode(binn_ptr(signatureObjBinn), binn_size(signatureObjBinn), NULL);
            //printf("Signature (base64) : %s\n", b64signatureObjBinn);

            sendmail(destinationID, userID, subject, nonceAesB64, timestampStr, ciphertextB64, b64signatureObjBinn, cipherB64, userID, password);
            free(nonceAesB64);
            free(ciphertextB64);
            free(b64signatureObjBinn);
            free(cipherB64);
            binn_free(signatureObjBinn);

            // ----------------------------------------------------------------------
            // Now the message is encrypted and authentified with an AES Key and the key is encrypted and signed using CLPKC
            // ----------------------------------------------------------------------

            free(message);
            free(subject);
            free(destinationID);

            free(destinationTimestamp);
            free(timestampStr);
            free(authenticatedData);
        }
        // If we want to decrypt an email
        else {
            checkmail(userID, password);

            DIR *dir;
            struct dirent *ent;
            if ((dir = opendir ("download")) != NULL) {
                /* print all the files and directories within directory */
                while ((ent = readdir (dir)) != NULL) {
                    if(strcmp(ent->d_name, ".") == 0 || strcmp(ent->d_name, "..") == 0)
                        continue;
                    printf("%s : Subject - > ", ent->d_name);
                    displaySubject(ent->d_name);
                    printf("\n");
                }
                closedir (dir);
            } else {
                /* could not open directory */
                perror ("");
                return EXIT_FAILURE;
            }
            printf("Choose a file to parse (filename): \n");
            char *fileChoice = malloc(256);
            memset(fileChoice, 0, 256);
            fgets(fileChoice, 256, stdin);
            fileChoice[strlen(fileChoice)-1] = '\x00';
            printf("filename  : %s", fileChoice);
            binn* emailObj = parseEmail(fileChoice);
            free(fileChoice);

            char *sourceAddress = binn_object_str(emailObj, "From");
            char *b64Signature = binn_object_str(emailObj, "X-SIGNATURE-B64");
            char *b64Cipher = binn_object_str(emailObj, "X-CIPHER-B64");
            char *b64Encrypted = binn_object_str(emailObj, "Body");
            char *b64Nonce = binn_object_str(emailObj, "X-AES-NONCE");
            char *subject = binn_object_str(emailObj, "Subject");
            char *timestamp = binn_object_str(emailObj, "X-TIMESTAMP-USED");
            if(b64Signature == NULL || b64Cipher == NULL || b64Encrypted == NULL || b64Nonce == NULL){
                printf("I cannot parse the email, it's not an email written by my POC\n");
                saveSecretsValue(secrets, userID, userPassword, &salt, &nonce);
                exit(EXIT_FAILURE);
            }
            char *IDUsed = malloc(330);
            memset(IDUsed, 0, 330);
            strcpy(IDUsed, userID);
            strcat(IDUsed, "+");
            strcat(IDUsed, timestamp);

            signature s;
            size_t outLen;
            unsigned char *signatureBinn = base64_decode(b64Signature, strlen(b64Signature), &outLen);
            deserialize_Signature(signatureBinn, &s);
            free(signatureBinn);
            cipher c;
            unsigned char *cipherBinn = base64_decode(b64Cipher, strlen(b64Cipher),&outLen);
            deserialize_Cipher(cipherBinn, &c);
            free(cipherBinn);

            // Computes the message to sign, so the cipher struct
            int c0size = gt_size_bin(c.c0, 1);
            int c1Size = g1_size_bin(c.c1, 1);
            int c2Size = g2_size_bin(c.c2, 1);
            int c3Size = g2_size_bin(c.c3, 1);
            uint8_t mSig[c0size + c1Size + c2Size + c3Size + strlen(b64Encrypted)];
            gt_write_bin(mSig, c0size, c.c0, 1);
            g1_write_bin(&mSig[c0size], c1Size, c.c1, 1);
            g2_write_bin(&mSig[c0size + c1Size], c2Size, c.c2, 1);
            g2_write_bin(&mSig[c0size + c1Size + c2Size], c3Size, c.c3, 1);
            memcpy(&mSig[c0size + c1Size + c2Size + c3Size], b64Encrypted, strlen(b64Encrypted));

            encryption_pk encryption_sourcePK;
            signature_pk signature_sourcePK;
            getPk(&encryption_sourcePK, &signature_sourcePK, sourceAddress);

            // We can go for decrypting and verification
            // We can verify directly with the public keys of the sender
            int test = verify(s, signature_sourcePK, mpkSignature, sourceAddress, mSig);
            printf("\nVerification of the key (0 if correct 1 if not) : %d\n", test);
            // if the verif is ok we can continue, otherwise we can stop here
            if(test == 0) {
                // For this we need our Partial Private Keys with the ID used to encrypt the message
                encryption_sk SecretKeysBob;
                signature_sk SecretKeysBobSig;
                getSecretKey(secrets, timestamp, mpkSession, mpkSignature, &SecretKeysBob, &SecretKeysBobSig, userID);

                // We can decrypt now
                gt_t decryptedMessage;
                gt_null(decryptedMessage)
                gt_new(decryptedMessage)
                decrypt(c, SecretKeysBob, encryptionPk, mpkSession, IDUsed, &decryptedMessage);

                char aeskDecrypted[crypto_secretbox_KEYBYTES];
                get_key(aeskDecrypted, decryptedMessage);

                size_t size_cipher;
                unsigned char *ciphertext = base64_decode(b64Encrypted, strlen(b64Encrypted), &size_cipher);
                unsigned char decrypted[size_cipher];
                memset(decrypted, 0, size_cipher);

                size_t nonceSize;
                unsigned char* nonceAES = base64_decode(b64Nonce, strlen(b64Nonce), &nonceSize);

                size_t authenticatedDataSize = strlen(sourceAddress) + strlen(userID) + strlen(subject) + 1;
                unsigned char *authenticatedData = malloc(authenticatedDataSize);
                memset(authenticatedData, 0, authenticatedDataSize);
                strcpy(authenticatedData, sourceAddress);
                strcat(authenticatedData, userID);
                strcat(authenticatedData, subject);
                decrypt_message(decrypted, ciphertext, nonceAES, aeskDecrypted, size_cipher, authenticatedData, authenticatedDataSize);
                printf("From : %s\n", sourceAddress);
                printf("To : %s\n", userID);
                printf("Subject : %s\n", subject);
                printf("Decrypted content : %s\n", decrypted);
                free(ciphertext);
                free(authenticatedData);
                free(nonceAES);
            }
            free(IDUsed);
            binn_free(emailObj);
        }
        saveSecretsValue(secrets, userID, userPassword, &salt, &nonce);
        binn_free(secrets);
        free(salt);
        free(nonce);
        free(charUserChoice);
        free(userID);
        free(password);
        free(userPassword);
        bn_zero(encryption_secret);
        bn_zero(signature_secret);
        bn_free(encryption_secret)
        bn_free(signature_secret)
    }
    core_clean();
}
