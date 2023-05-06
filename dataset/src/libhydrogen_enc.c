#include "hydrogen.h"
#include <stdio.h>

#define CONTEXT "Examples"
#define MESSAGE_LEN 200000000
#define CIPHERTEXT_LEN (hydro_secretbox_HEADERBYTES + MESSAGE_LEN)

int main(int argc, char const* argv[])
{

    uint8_t key[hydro_secretbox_KEYBYTES];
    uint8_t *ciphertext = malloc(CIPHERTEXT_LEN);

    FILE *fp = fopen(argv[1], "rb");
    fseek(fp, 0L, SEEK_END);
    int mlen = ftell(fp);

    char *message = malloc(mlen+1);

    fseek(fp, 0L, SEEK_SET);
    fread(message, mlen, 1, fp);

//#pragma tainter taint(key)
//#pragma tainter sinktaint(message)

    hydro_secretbox_keygen(key);
    hydro_secretbox_encrypt(ciphertext, message, mlen, 0, CONTEXT, key);

    char *decrypted = malloc(MESSAGE_LEN);
//#pragma tainter sinktaint(ciphertext)
    if (hydro_secretbox_decrypt(decrypted, ciphertext, CIPHERTEXT_LEN, 0, CONTEXT, key) != 0) {
        /* message forged! */
    }
    free(decrypted);
    free(ciphertext);

    return 0;
}
