/**
 * @file cipherPOC.h
 * @author Mickael Bonjour mickael.bonjour@heig-vd.ch
 * @date 14 mai 2020
 * @brief All the resources to encrypt/decrypt with a CL-PKC scheme using the RELIC library
 *        Encryption Scheme used : https://eprint.iacr.org/2007/121.pdf
 */
#include "signaturePOC.h"

void functionH2(g2_t* to_point, char* bytes_from, int len_bytes){
    uint8_t to_hash[len_bytes + 1];
    // Hash domain separation adding 1 byte \x01 before the actual data to hash
    to_hash[0] = '\x01';
    memcpy(to_hash + 1, bytes_from, len_bytes);
    g2_map(*to_point, to_hash, len_bytes + 1);
}

void functionH3(g2_t* to_point, char* bytes_from, int len_bytes){
    uint8_t to_hash[len_bytes + 1];
    // Hash domain separation adding 1 byte \x02 before the actual data to hash
    to_hash[0] = '\x02';
    memcpy(to_hash + 1, bytes_from, len_bytes);
    g2_map(*to_point, to_hash, len_bytes + 1);
}

void setupSig(int i, signature_mpk *mpk, bn_t *s){
    bn_t q;
    bn_null(*s)
    bn_new(*s)

    bn_null(q)
    bn_new(q)

    // q = Order of G1
    g1_get_ord(q);

    // s = random Zq
    bn_rand_mod(*s, q);

    g1_null(mpk->P)
    g1_new(mpk->P)
    g1_null(mpk->Ppub)
    g1_new(mpk->Ppub)
    // Choose a generator P
    g1_get_gen(mpk->P);
    // Setup Ppub = s*P
    g1_mul(mpk->Ppub, mpk->P, *s);

    bn_zero(q);
    bn_free(q)
}

void extractSig(signature_mpk mpk, bn_t msk, char* ID, signature_ppk * partialKeys) {
    g2_t qa;
    g2_null(qa)
    g2_new(qa)

    g2_null(partialKeys->D)
    g2_new(partialKeys->D)

    // Qa = H1(ID)
    g2_map(qa, ID, strlen(ID));
    // D = msk*Qa
    g2_mul(partialKeys->D, qa, msk);

    // TODO : Extract this
    // Test correctnes (for user only so we need to put it in a different function)
    gt_t test1, test2;
    gt_null(test1)
    gt_null(tet2)
    gt_new(test1)
    gt_new(test2)

    pc_map(test1, mpk.P, partialKeys->D);
    pc_map(test2, mpk.Ppub, qa);

    if (gt_cmp(test2, test1) == RLC_EQ) {
        printf("The partial private key extraction is correct !\n");
    }

    gt_set_unity(test1);
    gt_set_unity(test2);
    g2_set_infty(qa);

    gt_free(test2)
    gt_free(test1)
    g2_free(qa)
}

void setSecSig(bn_t* x){
    bn_t q;
    bn_null(q)
    bn_new(q)
    bn_null(*x)
    bn_new(*x)
    // q = Zq
    g1_get_ord(q);
    // x = random from Zq
    bn_rand_mod(*x, q);

    bn_zero(q);
    bn_free(q)
}

void setPubSig(bn_t x, signature_mpk mpkSession, signature_pk* PKtoGen){
    g1_null(PKtoGen->Ppub)
    g1_new(PKtoGen->Ppub)
    // Public key : Ppub = x*P
    g1_mul(PKtoGen->Ppub, mpkSession.P, x);
}

void setPrivSig(bn_t x, signature_ppk d, signature_mpk mpk, char* ID, signature_sk * secretKeys){
    g2_null(secretKeys->D)
    g2_new(secretKeys->D)

    bn_null(secretKeys->x)
    bn_new(secretKeys->x)
    // The private key is composed with D, the partial private key
    g2_copy(secretKeys->D, d.D);
    // And x the secret value
    bn_copy(secretKeys->x, x);
}

void sign(unsigned char* m, signature_sk sk, signature_pk pk, unsigned char* ID, signature_mpk mpk, signature* s){
    bn_t r, q;
    bn_null(r)
    bn_new(r)
    bn_null(q)
    bn_new(q)
    g1_get_ord(q);
    // r = random from Zq
    bn_rand_mod(r, q);

    //Computes U = r*P
    g1_null(s->U)
    g1_new(s->U)
    g1_mul(s->U, mpk.P, r);

    // Computes V = D + r*H2(m,ID,PK,U) + x*H3(m,ID,PK)
    g2_null(s->V)
    g2_new(s->V)
    g2_copy(s->V, sk.D);

    g2_t h2, h3;
    g2_null(h2)
    g2_null(h3)
    g2_new(h2)
    g2_new(h3)

    int PKsize = g1_size_bin(pk.Ppub, 1);
    int USize = g1_size_bin(s->U, 1);
    int lenConcat1 = strlen(ID) + strlen(m) + PKsize + USize;
    int lenConcat2 = strlen(ID) + strlen(m) + PKsize;

    // Construct H2(m,ID,PK,U) and H3(m,ID,PK)
    uint8_t concat1[lenConcat1], concat2[lenConcat2];
    strcpy(concat1, m);
    strcpy(concat2, m);
    strcpy(&concat1[strlen(m)], ID);
    strcpy(&concat2[strlen(m)], ID);

    g1_write_bin(&concat1[strlen(ID) + strlen(m)], PKsize, pk.Ppub, 1);
    g1_write_bin(&concat2[strlen(ID) + strlen(m)], PKsize, pk.Ppub, 1);

    g1_write_bin(&concat1[strlen(ID) + strlen(m) + PKsize], USize, s->U, 1);

    functionH2(&h2, concat1, lenConcat1);
    functionH3(&h3, concat2, lenConcat2);

    g2_mul(h2, h2, r);
    g2_mul(h3, h3, sk.x);

    g2_add(s->V, s->V, h2);
    g2_add(s->V, s->V, h3);

    bn_zero(r);
    bn_zero(q);
    bn_free(r)
    bn_free(q)
    g2_set_infty(h2);
    g2_set_infty(h3);
    g2_free(h2)
    g2_free(h3)
}

int verify(signature s, signature_pk pk, signature_mpk mpk, char* ID, unsigned char* m){
    // By default the signature is not verified
    int result = 1;

    g2_t qa;
    g2_null(qa)
    g2_new(qa)
    // Qa = H1(ID)
    g2_map(qa, ID, strlen(ID));

    // Computes leftOperand = e(P,V), rightOperand e(Ppub, Qa), temp e(U, H2(m,ID,PK,U))
    gt_t leftOperand, rightOperand, temp;
    gt_null(leftOperand)
    gt_null(rightOperand)
    gt_null(temp)
    gt_new(leftOperand)
    gt_new(rightOperand)
    gt_new(temp)
    // leftOPerand = e(P,V)
    pc_map(leftOperand, mpk.P, s.V);
    // rightOperand = e(Ppub, Qa)
    pc_map(rightOperand, mpk.Ppub, qa);


    g2_t h2, h3;
    g2_null(h2)
    g2_null(h3)
    g2_new(h2)
    g2_new(h3)

    int PKsize = g1_size_bin(pk.Ppub, 1);
    int USize = g1_size_bin(s.U, 1);
    int lenConcat1 = strlen(ID) + strlen(m) + PKsize + USize;
    int lenConcat2 = strlen(ID) + strlen(m) + PKsize;

    uint8_t concat1[lenConcat1], concat2[lenConcat2];
    strcpy(concat1, m);
    strcpy(concat2, m);
    strcpy(&concat1[strlen(m)], ID);
    strcpy(&concat2[strlen(m)], ID);

    g1_write_bin(&concat1[strlen(ID) + strlen(m)], PKsize, pk.Ppub, 1);
    g1_write_bin(&concat2[strlen(ID) + strlen(m)], PKsize, pk.Ppub, 1);
    g1_write_bin(&concat1[strlen(ID) + strlen(m) + PKsize], USize, s.U, 1);

    functionH2(&h2, concat1, lenConcat1);
    functionH3(&h3, concat2, lenConcat2);

    // temp = e(U, H2(m,ID,PK,U))
    pc_map(temp, s.U, h2);
    // rightOPerand = e(Ppub, Qa)*e(U, H2(m,ID,PK,U))
    gt_mul(rightOperand, rightOperand, temp);
    gt_null(temp)
    gt_new(temp)
    // temp = e(Ppub, H3(m,ID,PK))
    pc_map(temp, pk.Ppub, h3);
    // rightOperand = e(Ppub, Qa)*e(U, H2(m,ID,PK,U))*e(Ppub, H3(m,ID,PK))
    gt_mul(rightOperand, rightOperand, temp);

    // The signature is correct if e(P,V) = e(Ppub, Qa)*e(U, H2(m,ID,PK,U))*e(Ppub, H3(m,ID,PK))
    if (gt_cmp(leftOperand, rightOperand) == RLC_EQ) {
        result = 0;
    }

    gt_set_unity(leftOperand);
    gt_set_unity(rightOperand);
    gt_set_unity(temp);
    gt_free(leftOperand)
    gt_free(rightOperand)
    gt_free(temp)

    g2_set_infty(h2);
    g2_set_infty(h3);
    g2_set_infty(qa);
    g2_free(h2)
    g2_free(h3)
    g2_free(qa)

    return result;
}

void serialize_MPKS(binn* obj, signature_mpk mpks) {
    int sizeP = g1_size_bin(mpks.P, 1);
    uint8_t P[sizeP];
    g1_write_bin(P, sizeP, mpks.P, 1);
    binn_object_set_blob(obj, "P", P, sizeP);

    int sizePpub = g1_size_bin(mpks.Ppub, 1);
    uint8_t Ppub[sizePpub];
    g1_write_bin(Ppub, sizePpub, mpks.Ppub, 1);
    binn_object_set_blob(obj, "Ppub", Ppub, sizePpub);
}

void deserialize_MPKS(binn* obj, signature_mpk* newMpk){

    void *PBin;
    void *PpubBin;
    int sizeP, sizePpub;
    PpubBin = binn_object_blob(obj, "Ppub", &sizePpub);
    PBin = binn_object_blob(obj, "P", &sizeP);

    g1_read_bin(newMpk->P, PBin, sizeP);
    g1_read_bin(newMpk->Ppub, PpubBin, sizePpub);

    //binn_free(obj);
}
void serialize_PPKS(binn* obj, signature_ppk ppks){
    int sizeD = g2_size_bin(ppks.D, 1);
    uint8_t P[sizeD];
    g2_write_bin(P, sizeD, ppks.D, 1);
    binn_object_set_blob(obj, "D", P, sizeD);
}
void deserialize_PPKS(void* buffer, signature_ppk* newPpk){
    binn *obj;

    obj = binn_open(buffer);
    if (obj == 0) return;
    void *DBin;
    int sizeD;
    DBin = binn_object_blob(obj, "D", &sizeD);

    g2_read_bin(newPpk->D, DBin, sizeD);

    binn_free(obj);
}

void serialize_PKS(binn* obj, signature_pk pks){
    int sizePpub = g1_size_bin(pks.Ppub, 1);
    uint8_t Ppub[sizePpub];
    g1_write_bin(Ppub, sizePpub, pks.Ppub, 1);
    binn_object_set_blob(obj, "Ppub", Ppub, sizePpub);
}

void deserialize_PKS(void* buffer, signature_pk* newPk){
    binn *obj;

    obj = binn_open(buffer);
    if (obj == 0) return;
    void *PpubBin;
    int sizePpub;
    PpubBin = binn_object_blob(obj, "Ppub", &sizePpub);

    g1_read_bin(newPk->Ppub, PpubBin, sizePpub);

    binn_free(obj);
}

void serialize_SKS(binn* obj, signature_sk sk){
    int sizeD, sizeX;
    sizeD = g2_size_bin(sk.D, 1);
    sizeX = bn_size_bin(sk.x);
    uint8_t DBin[sizeD], XBin[sizeX];
    g2_write_bin(DBin, sizeD, sk.D, 1);
    bn_write_bin(XBin, sizeX, sk.x);
    binn_object_set_blob(obj, "D", DBin, sizeD);
    binn_object_set_blob(obj, "X", XBin, sizeX);
}

void deserialize_SKS(binn* obj, signature_sk *sk){
    void *DBin, *XBin;
    int sizeD, sizeX;
    DBin = binn_object_blob(obj, "D", &sizeD);
    XBin = binn_object_blob(obj, "x", &sizeX);

    g2_read_bin(sk->D, DBin, sizeD);
    bn_new(sk->x)
    bn_null(sk->x)
    bn_read_bin(sk->x, XBin, sizeX);
    //binn_free(obj);
}

void serialize_Signature(binn* obj, signature s){
    int sizeU, sizeV;
    sizeU = g1_size_bin(s.U, 1);
    sizeV = g2_size_bin(s.V, 1);
    uint8_t UBin[sizeU], VBin[sizeV];
    g1_write_bin(UBin, sizeU, s.U, 1);
    g2_write_bin(VBin, sizeV, s.V, 1);
    binn_object_set_blob(obj, "U", UBin, sizeU);
    binn_object_set_blob(obj, "V", VBin, sizeV);
}

void deserialize_Signature(void* buffer, signature *s){
    binn *obj;
    obj = binn_open(buffer);

    void *UBin, *VBin;
    int sizeU, sizeV;
    UBin = binn_object_blob(obj, "U", &sizeU);
    VBin = binn_object_blob(obj, "V", &sizeV);

    g1_read_bin(s->U, UBin, sizeU);
    g2_read_bin(s->V, VBin, sizeV);
    binn_free(obj);
}
