/*****************************************************************************
 *                                                                           *
 *  Permission is hereby granted, free of charge, to any person obtaining    *
 *  a copy of this software and associated documentation files (the          *
 *  "Software"), to deal in the Software without restriction, including      *
 *  without limitation the rights to use, copy, modify, merge, publish,      *
 *  distribute, sublicense, and/or sell copies of the Software, and to       *
 *  permit persons to whom the Software is furnished to do so, subject to    *
 *  the following conditions:                                                *
 *                                                                           *
 *  The above copyright notice and this permission notice shall be included  *
 *  in all copies or substantial portions of the Software.                   *
 *                                                                           *
 *  THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,          *
 *  EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF       *
 *  MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.   *
 *  IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY     *
 *  CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT,     *
 *  TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE        *
 *  SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.                   *
 *                                                                           *
 *****************************************************************************/

#include <stdio.h>
#include <libotr/proto.h>
#include <libotr/instag.h>
#include <libotr/privkey.h>
#include <libotr/userstate.h>

#ifndef OTRL_PRIVKEY_FPRINT_HUMAN_LEN
#define OTRL_PRIVKEY_FPRINT_HUMAN_LEN 45
#endif

int main()
{
    printf("Label 0\n"); fflush(stdout);

    OtrlUserState userstate;

    printf("Label 1\n"); fflush(stdout);

    OTRL_INIT;

    printf("Label 2\n"); fflush(stdout);

    userstate = otrl_userstate_create();

    printf("Label 3\n"); fflush(stdout);

    const char *accountname = "random_jid@example.com";
    const char *protocol = "prpl-jabber";
    const char *keys_file = "otr.keys";

    void *newkeyp = NULL;
    if (otrl_privkey_generate_start(userstate, accountname, protocol, &newkeyp) == gcry_error(GPG_ERR_EEXIST)) {
        printf("libotr reports it's still generating a previous key while it shouldn't be"); fflush(stdout);
        return 1;
    }

    printf("Label 4\n"); fflush(stdout);

    if (otrl_privkey_generate_calculate(newkeyp) == gcry_error(GPG_ERR_NO_ERROR)) {
        otrl_privkey_generate_finish(userstate, newkeyp, keys_file);
    }
    else {
        printf("Kill all humans!111\n"); fflush(stdout);
        return 1;
    }

    printf("Label 5\n"); fflush(stdout);

    char fingerprint[OTRL_PRIVKEY_FPRINT_HUMAN_LEN];
    if (otrl_privkey_fingerprint(userstate, fingerprint, accountname, protocol))
    {
        printf("Keys have been generated. Fingerprint for account \"%s\":\n"
               "%s\n"
               "Thanks for your patience!\n",
               accountname,
               fingerprint
              );
        fflush(stdout);
    }
    else
    {
        printf("Failed to generate keys for account \"%s\".", accountname);
        fflush(stdout);
        return 1;
    }

    otrl_userstate_free(userstate);

    printf("Label 6\n"); fflush(stdout);

    return 0;
}

