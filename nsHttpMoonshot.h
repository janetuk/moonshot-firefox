/* The contents of this file are subject to the Mozilla Public License Version
 * 1.1 (the "License"); you may not use this file except in compliance with
 * the License. You may obtain a copy of the License at
 * http://www.mozilla.org/MPL/
 *
 * Software distributed under the License is distributed on an "AS IS" basis,
 * WITHOUT WARRANTY OF ANY KIND, either express or implied. See the License
 * for the specific language governing rights and limitations under the
 * License.
 *
 * The Original Code is the Negotiateauth
 *
 * The Initial Developer of the Original Code is Daniel Kouril.
 * Portions created by the Initial Developer are Copyright (C) 2003
 * the Initial Developer. All Rights Reserved.
 *
 * Contributor(s):
 *   Daniel Kouril <kouril@ics.muni.cz> (original author)
 *   Wyllys Ingersoll <wyllys.ingersoll@sun.com>
 *   Christopher Nebergall <cneberg@sandia.gov>
 */

#ifndef nsMoonshot_h__
#define nsMoonshot_h__

#include "nsIHttpAuthenticator.h"

#include <gssapi.h>
#include <gssapi/gssapi_ext.h>

#define NS_HTTPMOONSHOT_CID \
{ /* 75c80fd0-accb-432c-af59-ec60668c3991 */         \
    0x75c80fd0,                                      \
    0xaccb,                                          \
    0x432c,                                          \
    {0xaf, 0x59, 0xec, 0x60, 0x66, 0x8c, 0x39, 0x91} \
}

#define NS_HTTP_AUTHENTICATOR_CONTRACTID 	\
	"@mozilla.org/network/http-authenticator;1?scheme=gssapi"

#define NEGOTIATE_AUTH "GSSAPI"

class nsHttpMoonshot : public nsIHttpAuthenticator
#if 0
,
			 public nsIHttpAuthenticator_1_9_2
#endif
{
   public:
      NS_DECL_ISUPPORTS
      NS_DECL_NSIHTTPAUTHENTICATOR
#if 0
      NS_DECL_NSIHTTPAUTHENTICATOR_1_9_2
#endif


      nsHttpMoonshot();
      virtual ~nsHttpMoonshot();


      NS_IMETHODIMP
      GenerateCredentials_1_9_2(nsIHttpChannel *httpChannel,
                                               const char *challenge,
                                               PRBool isProxyAuth,
                                               const PRUnichar *domain,
                                               const PRUnichar *username,
                                               const PRUnichar *password,
                                               nsISupports **sessionState,
                                               nsISupports **continuationState,
                                               PRUint32 *flags,
                                               char **creds);

   private:
      void LogGssError(OM_uint32 maj, OM_uint32 min, char *prefix);
};
#endif /* nsMoonshot_h__ */
