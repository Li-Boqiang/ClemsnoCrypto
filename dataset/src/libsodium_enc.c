#include <sodium.h>
#include <stdio.h>


int main(int argc, char const* argv[]) {
    if (sodium_init() < 0) {
        /* panic! the library couldn't be initialized, it is not safe to use */
    }

    FILE *fp = fopen(argv[1], "rb");
	fseek(fp, 0L, SEEK_END);
	int plen = ftell(fp);
	char *ptext_ex = malloc(plen+1);
    fseek(fp, 0L, SEEK_SET);
    fread(ptext_ex, plen, 1, fp);

#define CIPHERTEXT_PART1_LEN plen + crypto_secretstream_xchacha20poly1305_ABYTES

    crypto_secretstream_xchacha20poly1305_state state;
    unsigned char key[crypto_secretstream_xchacha20poly1305_KEYBYTES];
    unsigned char header[crypto_secretstream_xchacha20poly1305_HEADERBYTES];
    unsigned char *c1 = malloc(CIPHERTEXT_PART1_LEN);

    /* Shared secret key required to encrypt/decrypt the stream */
    crypto_secretstream_xchacha20poly1305_keygen(key);

//#pragma tainter taint(key)

    /* Set up a new stream: initialize the state and create the header */
    crypto_secretstream_xchacha20poly1305_init_push(&state, header, key);

    /* Now, encrypt the first chunk. `c1` will contain an encrypted,
     * authenticated representation of `MESSAGE_PART1`. */

//#pragma tainter sinktaint(ptext_ex)
    crypto_secretstream_xchacha20poly1305_push
        (&state, c1, NULL, ptext_ex, plen, NULL, 0, 0);

    free(c1);
    return 0;
}
