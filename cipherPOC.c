/**
 * @file cipherPOC.h
 * @author Mickael Bonjour mickael.bonjour@heig-vd.ch
 * @date 14 mai 2020
 * @brief All the resources to encrypt/decrypt with a CL-PKC scheme using the RELIC library
 *        Encryption Scheme used : https://eprint.iacr.org/2007/121.pdf
 */

#include "cipherPOC.h"

void setup(int k, encryption_mpk* mpkSetup, g2_t* msk){
    //TODO nullify struct and init it (g1_new())
    bn_t p, gamma, uvGen;
    bn_null(p)
    bn_null(gamma)
    bn_null(uvGen)
    bn_new(p)
    bn_new(gamma)
    bn_new(uvGen)

    g1_null(mpkSetup->g)
    g1_null(mpkSetup->g1)
    g2_null(mpkSetup->g2)
    g1_new(mpkSetup->g)
    g1_new(mpkSetup->g1)
    g2_new(mpkSetup->g2)
    // g = generator of G1
    g1_get_gen(mpkSetup->g);
    g1_get_ord(p);

    // gamma = random from Zp
    bn_rand_mod(gamma, p);
    // g1 = gamma*g
    g1_mul(mpkSetup->g1, mpkSetup->g, gamma);
    // g2 = generator of G2
    g2_get_gen(mpkSetup->g2);

    g2_get_ord(p);
    // Generate 2 arrays with G2 elements for the U and  vectors
    for(int i =0; i < MESSAGE_SPACE; ++i){
        g2_null(mpkSetup->u[i])
        g2_null(mpkSetup->v[i])
        g2_new(mpkSetup->u[i])
        g2_new(mpkSetup->v[i])

        bn_rand_mod(uvGen,p);
        g2_mul(mpkSetup->u[i], mpkSetup->g2, uvGen);
        bn_rand_mod(uvGen,p);
        g2_mul(mpkSetup->v[i], mpkSetup->g2, uvGen);
    }

    // The master secret key is msk = gamma*g2
    g2_mul(*msk, mpkSetup->g2, gamma);

    bn_zero(gamma);
    bn_zero(p);
    bn_zero(uvGen);

    bn_free(gamma)
    bn_free(p)
    bn_free(uvGen)
}

void F(const char *var, g2_t* suite, g2_t *result, int size) {
    uint8_t h[RLC_MD_LEN];
    // Strlen ok car effectué sur des IDs donc vrais chaines de chars
    md_map(h, (uint8_t*) var, size);

    // Premier à ajouter
    g2_copy(*result, suite[0]);
    g2_t currentPoint;
    g2_null(currentPoint)
    g2_new(currentPoint)

    bn_t transitionToBn;
    bn_null(transitionToBn)
    bn_new(transitionToBn)
    // On parcourt byte par byte le hash
    for(int i = 0; i < 32; ++i){
        uint8_t somebyte = h[i];
        uint8_t currentBit;
        // On parcourt bit par bit le byte courrant
        for (int j = 0; j < 8; ++j, somebyte >>= 1) {
            currentBit = somebyte & 0x1;
            // le bit est transformé en bn_t pour pouvoir faire la multiplication avec l'élément de G2
            bn_read_bin(transitionToBn, &currentBit, 1);
            g2_mul(currentPoint, suite[(i*8) + j + 1], transitionToBn);
            // Ajout au total
            g2_add(*result, *result, currentPoint)
            //g2_null(currentPoint)
        }
    }
    g2_set_infty(currentPoint);
    bn_zero(transitionToBn);

    g2_free(currentPoint)
    bn_free(transitionToBn)
}

void extract(encryption_mpk mpk, g2_t msk, char* ID, encryption_ppk* partialKeys){
    bn_t p, r;
    bn_null(p)
    bn_null(r)
    bn_new(p)
    bn_new(r)

    g2_null(partialKeys->d1)
    g2_new(partialKeys->d1)

    g1_null(partialKeys->d2)
    g1_new(partialKeys->d2)

    g1_get_ord(p);
    // r random from Zp
    bn_rand_mod(r,p);

    // Computes d1 = msk + r*Fu(ID)
    g2_t temp;
    g2_null(temp)
    g2_new(temp)

    F(ID, mpk.u, &temp, strlen(ID));
    g2_mul(temp, temp, r);
    g2_add(partialKeys->d1, msk, temp);

    // Computes d2 = r*g
    g1_mul(partialKeys->d2, mpk.g, r);

    g2_set_infty(temp);
    bn_zero(p);
    bn_zero(r);
    bn_free(p)
    bn_free(r)
    g2_free(temp)
}

void setSec(bn_t* x){
    bn_t p;
    bn_null(p)
    bn_new(p)

    g1_get_ord(p);
    bn_rand_mod(*x, p);

    bn_zero(p);
    bn_free(p)
}

void setPub(bn_t x, encryption_mpk mpkSession, encryption_pk* PKtoGen){
    g2_mul(PKtoGen->X, mpkSession.g2, x);
    g1_mul(PKtoGen->Y, mpkSession.g1, x);
}

void setPriv(bn_t x, encryption_ppk d, encryption_mpk mpk, char* ID, encryption_sk* secretKeys){
    bn_t p, r;
    bn_null(p)
    bn_new(p)
    bn_null(r)
    bn_new(r)

    g1_get_ord(p);
    bn_rand_mod(r, p);

    // Computes s1 = x*d1 + r*Fu(ID)
    g2_t pointTemp;
    g2_null(pointTemp)
    g2_new(pointTemp)

    g2_mul(secretKeys->s1,d.d1, x);
    F(ID, mpk.u, &pointTemp, strlen(ID));
    g2_mul(pointTemp, pointTemp, r);
    g2_add(secretKeys->s1, secretKeys->s1, pointTemp);

    // Computes s2 = x*d2 + r*g
    g1_t temp;
    g1_null(temp)
    g1_new(temp)

    g1_mul(secretKeys->s2, d.d2, x);
    g1_mul(temp, mpk.g, r);
    g1_add(secretKeys->s2, secretKeys->s2, temp);

    bn_zero(r);
    bn_zero(p);
    g1_set_infty(temp);
    g2_set_infty(pointTemp);

    bn_free(r)
    bn_free(p)
    g1_free(temp)
    g2_free(pointTemp)
}

void encrypt(gt_t m, encryption_pk pk, unsigned char* ID, encryption_mpk mpk, cipher* c){
    bn_t p, s;
    bn_null(p)
    bn_null(s)
    bn_new(p)
    bn_new(s)

    //TODO: Check before ? e(X, g1)/e(g, Y) = 1GT
    g1_get_ord(p);
    bn_rand_mod(s, p);

    // Instantiate our struct
    gt_null(c->c0)
    gt_new(c->c0)

    g1_null(c->c1)
    g1_new(c->c1)

    g2_null(c->c2)
    g2_null(c->c3)
    g2_new(c->c2)
    g2_new(c->c3)

    // Computes C0 = e(Y,g2)^s*m
    gt_t temp;
    gt_null(temp)
    gt_new(temp)
    pc_map(temp, pk.Y, mpk.g2);
    gt_exp(temp, temp, s);
    gt_mul(c->c0, m, temp)
    gt_free(temp)

    // Computes C1 = s*g
    g1_mul(c->c1, mpk.g, s);

    // Computes C2 = s*Fu(ID)
    g2_t pointTemp;
    g2_null(pointTemp)
    g2_new(pointTemp)
    F(ID, mpk.u, &pointTemp, strlen(ID));
    g2_mul(c->c2, pointTemp, s);
    g2_free(pointTemp)

    // Computes C3 = s*Fv(w) où w = C0, C1, C2, ID, PK.x, PK.y
    g2_t pointTemp2;
    g2_null(pointTemp2)
    g2_new(pointTemp2)

    // Construction of the w bytes object to hash
    int c0size = gt_size_bin(c->c0,1);
    int c1Size = g1_size_bin(c->c1, 1);
    int c2Size = g2_size_bin(c->c2, 1);
    int pkXSize = g2_size_bin(pk.X, 1);
    int pkYSize = g1_size_bin(pk.Y, 1);
    uint8_t w[c0size + c1Size + c2Size + strlen(ID) + pkXSize + pkYSize];
    gt_write_bin(w, c0size, c->c0, 1);
    g1_write_bin(&w[c0size], c1Size, c->c1, 1);
    g2_write_bin(&w[c0size + c1Size], c2Size, c->c2, 1);
    strcpy(&w[c0size + c1Size + c2Size], ID);
    g2_write_bin(&w[c0size + c1Size + c2Size + strlen(ID)], pkXSize, pk.X, 1);
    g1_write_bin(&w[c0size + c1Size + c2Size + strlen(ID) + pkXSize], pkYSize, pk.Y, 1);

    F(w, mpk.v, &pointTemp2, c0size + c1Size + c2Size + strlen(ID) + pkXSize + pkYSize);
    g2_mul(c->c3, pointTemp2, s);

    bn_zero(p);
    bn_zero(s);
    g2_set_infty(pointTemp);
    g2_set_infty(pointTemp2);
    gt_set_unity(temp);
    bn_free(p)
    bn_free(s)
    g2_free(pointTemp)
    g2_free(pointTemp2)
    gt_free(temp)
}

void decrypt(cipher c, encryption_sk sk, encryption_pk pk, encryption_mpk  mpk, char* ID, gt_t* m){
    /* Vesrion fonctionelle (sans vérifications)
     * gt_t numerateur;
    gt_t denominateur;

    pc_map(numerateur, sk.s2, C.c2);
    pc_map(denominateur, C.c1, sk.s1);
    gt_inv(denominateur, denominateur);
    gt_mul(*m, numerateur, denominateur);
    gt_mul(*m, C.c0, *m);
     */
    // Take alpha randomly from Zp
    bn_t alpha, p;
    bn_null(alpha)
    bn_null(p)
    bn_new(alpha)
    bn_new(p)
    g1_get_ord(p);
    bn_rand_mod(alpha, p);
    bn_free(p)

    g2_t pointFv;
    g2_t pointFu;
    g2_null(pointFv)
    g2_null(pointFu)
    g2_new(pointFv)
    g2_new(pointFu)

    // Construction of the w bytes object to hash (e(Ppub, Qa)*e(U, H2(m,ID,PK,U))*e(Ppub, H3(m,ID,PK)))
    int c0size = gt_size_bin(c.c0,1);
    int c1Size = g1_size_bin(c.c1, 1);
    int c2Size = g2_size_bin(c.c2, 1);
    int pkXSize = g2_size_bin(pk.X, 1);
    int pkYSize = g1_size_bin(pk.Y, 1);
    uint8_t w[c0size + c1Size + c2Size + strlen(ID) + pkXSize + pkYSize];
    gt_write_bin(w, c0size, c.c0, 1);
    g1_write_bin(&w[c0size], c1Size, c.c1, 1);
    g2_write_bin(&w[c0size + c1Size], c2Size, c.c2, 1);
    strcpy(&w[c0size + c1Size + c2Size], ID);
    g2_write_bin(&w[c0size + c1Size + c2Size + strlen(ID)], pkXSize, pk.X, 1);
    g1_write_bin(&w[c0size + c1Size + c2Size + strlen(ID) + pkXSize], pkYSize, pk.Y, 1);
    // Constructs our point
    F(w, mpk.v, &pointFv, c0size + c1Size + c2Size + strlen(ID) + pkXSize + pkYSize);
    F(ID, mpk.u, &pointFu, strlen(ID));

    // m = numerateur * numerateur2 / denominateur
    gt_t numerateur, denominateur, numerateur2;
    g1_t alphaG, tempNumerateur;
    g2_t Fpoints;
    gt_null(numerateur)
    gt_null(numerateur2)
    gt_null(denominateur)
    g1_null(tempNumerateur)
    gt_new(numerateur)
    gt_new(numerateur2)
    gt_new(denominateur)
    g1_new(tempNumerateur)

    g1_null(alphaG)
    g2_null(Fpoints)
    g1_new(alphaG)
    g2_new(Fpoints)
    // alphaG = alpha * g
    g1_mul(alphaG, mpk.g, alpha);
    g1_add(tempNumerateur, sk.s2, alphaG);
    // numerateur = e(s2 + alphaG, C2)
    pc_map(numerateur, tempNumerateur, c.c2);
    // numerateur2 = e(alphaG, C3)
    pc_map(numerateur2, alphaG, c.c3);
    gt_mul(numerateur, numerateur, numerateur2);

    g2_mul(pointFu, pointFu, alpha);
    g2_mul(pointFv, pointFv, alpha);

    g2_add(Fpoints, sk.s1, pointFu)
    g2_add(Fpoints,Fpoints, pointFv)
    pc_map(denominateur, c.c1, Fpoints);

    gt_inv(denominateur, denominateur);
    gt_mul(*m, numerateur, denominateur);
    gt_mul(*m, c.c0, *m);

    bn_zero(alpha);
    bn_zero(p);
    g2_set_infty(pointFv);
    g2_set_infty(pointFu);
    g1_set_infty(alphaG);
    g2_set_infty(Fpoints);
    gt_set_unity(numerateur);
    gt_set_unity(numerateur2);
    g1_set_infty(tempNumerateur);
    gt_set_unity(denominateur);

    bn_free(alpha)
    bn_free(p)
    g2_free(pointFv)
    g2_free(pointFu)
    g1_free(alphaG)
    g2_free(Fpoints)
    gt_free(numerateur)
    gt_free(numerateur2)
    g1_free(tempNumerateur)
    gt_free(denominateur)
}

void serialize_MPKE(binn* obj, encryption_mpk mpke){
    binn *listU, *listV;
    listU = binn_list();
    listV = binn_list();
    int sizeG,sizeG1, sizeG2;
    sizeG = g1_size_bin(mpke.g, 1);
    sizeG1 = g1_size_bin(mpke.g1, 1);
    sizeG2 = g2_size_bin(mpke.g2, 1);
    uint8_t GBin[sizeG], G1Bin[sizeG1], G2Bin[sizeG2];
    g1_write_bin(GBin,sizeG, mpke.g,1);
    g1_write_bin(G1Bin,sizeG1, mpke.g1,1);
    g2_write_bin(G2Bin,sizeG2, mpke.g2,1);
    binn_object_set_blob(obj, "G", GBin, sizeG);
    binn_object_set_blob(obj, "G1", G1Bin, sizeG1);
    binn_object_set_blob(obj, "G2", G2Bin, sizeG2);
    int currentUSize, currentVSize;
    for(int i = 0; i < MESSAGE_SPACE; ++i) {
        currentUSize = g2_size_bin(mpke.u[i], 1);
        currentVSize = g2_size_bin(mpke.v[i], 1);
        uint8_t *currentUBin = malloc(currentUSize);
        uint8_t *currentVBin = malloc(currentVSize);
        g2_write_bin(currentUBin, currentUSize, mpke.u[i], 1);
        g2_write_bin(currentVBin, currentVSize, mpke.v[i], 1);
        binn_list_add_blob(listU, currentUBin, currentUSize);
        binn_list_add_blob(listV, currentVBin, currentVSize);
        free(currentUBin);
        free(currentVBin);
    }

    binn_object_set_list(obj, "U", listU);
    binn_object_set_list(obj, "V", listV);
    binn_free(listU);
    binn_free(listV);
}
void deserialize_MPKE(binn* obj, encryption_mpk* newMpk){
    binn *listU, *listV;
    void *g, *g1, *g2;
    int sizeG, sizeG1, sizeG2;
    g = binn_object_blob(obj, "G", &sizeG);
    g1 = binn_object_blob(obj, "G1", &sizeG1);
    g2 = binn_object_blob(obj, "G2", &sizeG2);

    g1_read_bin(newMpk->g, g, sizeG);
    g1_read_bin(newMpk->g1, g1, sizeG1);
    g2_read_bin(newMpk->g2, g2, sizeG2);

    listU = binn_object_list(obj, "U");
    listV = binn_object_list(obj, "V");
    int countU, countV;
    countU = binn_count(listU);
    countV = binn_count(listV);
    void* currentBin;
    int currentSize;
    for(int i = 1; i <= countU; ++i){
        currentBin = binn_list_blob(listU, i, &currentSize);
        g2_read_bin(newMpk->u[i-1], currentBin, currentSize);
        binn_list_get_blob(listV, i,&currentBin, &currentSize);
        g2_read_bin(newMpk->v[i-1], currentBin, currentSize);
    }
    //binn_free(listU);
    //binn_free(listV);
    //binn_free(obj);
}

void serialize_PPKE(binn* obj, encryption_ppk ppke){
    int sizeD1, sizeD2;
    sizeD1 = g2_size_bin(ppke.d1, 1);
    sizeD2 = g1_size_bin(ppke.d2, 1);
    uint8_t  d1Bin[sizeD1], d2Bin[sizeD2];
    g2_write_bin(d1Bin, sizeD1, ppke.d1, 1);
    g1_write_bin(d2Bin,sizeD2, ppke.d2, 1);
    binn_object_set_blob(obj, "D1", d1Bin, sizeD1);
    binn_object_set_blob(obj, "D2", d2Bin, sizeD2);
}
void deserialize_PPKE(void* buffer, encryption_ppk* newPpk){
    binn* obj;
    obj = binn_open(buffer);
    int sizeD1, sizeD2;
    void *d1, *d2;
    d1 = binn_object_blob(obj, "D1", &sizeD1);
    d2 = binn_object_blob(obj, "D2", &sizeD2);
    g2_read_bin(newPpk->d1, d1, sizeD1);
    g1_read_bin(newPpk->d2, d2, sizeD2);
    binn_free(obj);
}

void serialize_PKE(binn* obj, encryption_pk pk){
    int sizeX, sizeY;
    sizeX = g2_size_bin(pk.X, 1);
    sizeY = g1_size_bin(pk.Y, 1);
    uint8_t  xBin[sizeX], yBin[sizeY];
    g2_write_bin(xBin, sizeX, pk.X, 1);
    g1_write_bin(yBin,sizeY, pk.Y, 1);
    binn_object_set_blob(obj, "X", xBin, sizeX);
    binn_object_set_blob(obj, "Y", yBin, sizeY);
}

void deserialize_PKE(void* buffer, encryption_pk* newPk){
    binn* obj;
    obj = binn_open(buffer);
    int sizeX, sizeY;
    void *x, *y;
    x = binn_object_blob(obj, "X", &sizeX);
    y = binn_object_blob(obj, "Y", &sizeY);
    g2_read_bin(newPk->X, x, sizeX);
    g1_read_bin(newPk->Y, y, sizeY);
    binn_free(obj);
}

void serialize_SKE(binn* obj, encryption_sk sk){
    int sizeS1, sizeS2;
    sizeS1 = g2_size_bin(sk.s1, 1);
    sizeS2 = g1_size_bin(sk.s2, 1);
    uint8_t  s1Bin[sizeS1], s2Bin[sizeS2];
    g2_write_bin(s1Bin, sizeS1, sk.s1, 1);
    g1_write_bin(s2Bin,sizeS2, sk.s2, 1);
    binn_object_set_blob(obj, "s1", s1Bin, sizeS1);
    binn_object_set_blob(obj, "s2", s2Bin, sizeS2);
}

void deserialize_SKE(binn* obj, encryption_sk *sk){
    int sizeS1, sizeS2;
    void *s1, *s2;
    s1 = binn_object_blob(obj, "s1", &sizeS1);
    s2 = binn_object_blob(obj, "s2", &sizeS2);
    g2_read_bin(sk->s1, s1, sizeS1);
    g1_read_bin(sk->s2, s2, sizeS2);
    //binn_free(obj);
}


void serialize_Cipher(binn* obj, cipher c){
    int sizeC0, sizeC1, sizeC2, sizeC3;
    sizeC0 = gt_size_bin(c.c0, 1);
    sizeC1 = g1_size_bin(c.c1, 1);
    sizeC2 = g2_size_bin(c.c2, 1);
    sizeC3 = g2_size_bin(c.c3, 1);
    uint8_t c0Bin[sizeC0], c1Bin[sizeC1], c2Bin[sizeC2], c3Bin[sizeC3];
    gt_write_bin(c0Bin, sizeC0, c.c0, 1);
    g1_write_bin(c1Bin, sizeC1, c.c1, 1);
    g2_write_bin(c2Bin, sizeC2, c.c2, 1);
    g2_write_bin(c3Bin, sizeC3, c.c3, 1);
    binn_object_set_blob(obj, "C0", c0Bin, sizeC0);
    binn_object_set_blob(obj, "C1", c1Bin, sizeC1);
    binn_object_set_blob(obj, "C2", c2Bin, sizeC2);
    binn_object_set_blob(obj, "C3", c3Bin, sizeC3);
}

void deserialize_Cipher(void* buffer, cipher* c){
    binn* obj;
    obj = binn_open(buffer);
    int sizeC0, sizeC1, sizeC2, sizeC3;
    void *c0Bin, *c1Bin, *c2Bin, *c3Bin;

    c0Bin = binn_object_blob(obj, "C0", &sizeC0);
    c1Bin = binn_object_blob(obj, "C1", &sizeC1);
    c2Bin = binn_object_blob(obj, "C2", &sizeC2);
    c3Bin = binn_object_blob(obj, "C3", &sizeC3);

    gt_read_bin(c->c0, c0Bin, sizeC0);
    g1_read_bin(c->c1, c1Bin, sizeC1);
    g2_read_bin(c->c2, c2Bin, sizeC2);
    g2_read_bin(c->c3, c3Bin, sizeC3);

    binn_free(obj);
}