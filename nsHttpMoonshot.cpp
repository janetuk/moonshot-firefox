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

//
// GSSAPI Authentication Support Module
//
// Described by IETF Internet draft: draft-brezak-kerberos-http-00.txt
// (formerly draft-brezak-spnego-http-04.txt)
//
// Also described here:
// http://msdn.microsoft.com/library/default.asp?url=/library/en-us/dnsecure/html/http-sso-1.asp
//
//

/* this #define must run before prlog.h is included */
#define FORCE_PR_LOG 1

#include <stdlib.h>
#include "nsCOMPtr.h"
#include "nsIHttpChannel.h"
#include "nsIServiceManager.h"
#include "nsISupportsPrimitives.h"
#include "nsIURI.h"
#include "plbase64.h"
#include "plstr.h"
#include "prprf.h"
#include "prlog.h"
#include "prmem.h"
#include "nsISupportsUtils.h"

/* XXX, just for debugging */
#ifdef MOZILLA_INTERNAL_API
#include "nsString.h"
#else
#include "nsStringAPI.h"
#endif

/* HACK: */
#include <ctype.h>


#include "nsMoonshotSessionState.h"
#include "nsHttpMoonshot.h"

/* #define HAVE_GSS_C_NT_HOSTBASED_SERVICE 1 */
#include <gssapi.h>
#ifndef HAVE_GSS_C_NT_HOSTBASED_SERVICE 
#ifndef HEIMDAL
 #include <gssapi/gssapi_generic.h> 
#endif
#endif

static gss_OID_desc gss_krb5_mech_oid_desc =
{9, (void *)"\x2a\x86\x48\x86\xf7\x12\x01\x02\x02"};

static gss_OID_desc gss_spnego_mech_oid_desc = 
{6, (void *)"\x2b\x06\x01\x05\x05\x02"};

// in order to do logging, the following environment variables need to be set:
// 
//      set NSPR_LOG_MODULES=negotiate:4
//      set NSPR_LOG_FILE=negotiate.log

#if defined(PR_LOGGING)

    PRLogModuleInfo *gHttpLog = nsnull;
    static PRLogModuleInfo* gNegotiateLog = nsnull;

#endif

 #define LOG4(args) PR_LOG(gNegotiateLog, 4, args)
 #define LOG(args) LOG4(args)

static void
parse_oid(char *mechanism, gss_OID * oid)
{
    char   *mechstr = 0;
    gss_buffer_desc tok;
    OM_uint32 maj_stat, min_stat;
    size_t i, mechlen = strlen(mechanism);

    if (isdigit((int) mechanism[0])) {
        mechstr = (char *)malloc(mechlen + 5);
        if (!mechstr) {
            fprintf(stderr, "Couldn't allocate mechanism scratch!\n");
            return;
        }
        mechstr[0] = '{';
        mechstr[1] = ' ';
        for (i = 0; i < mechlen; i++)
            mechstr[i + 2] = (mechanism[i] == '.') ? ' ' : mechanism[i];
        mechstr[mechlen + 2] = ' ';
        mechstr[mechlen + 3] = ' ';
        mechstr[mechlen + 4] = '\0';
        tok.value = mechstr;
    } else
        tok.value = mechanism;
    tok.length = strlen((const char *)tok.value);
    maj_stat = gss_str_to_oid(&min_stat, &tok, oid);
    if (maj_stat != GSS_S_COMPLETE) {
        //display_status("str_to_oid", maj_stat, min_stat);
        return;
    }
    if (mechstr)
        free(mechstr);
}

gss_OID
GetOID()
{
    gss_OID mech_oid;

    parse_oid("{1 3 6 1 4 1 5322 22 1 18}", &mech_oid);
    return mech_oid;
}

nsHttpMoonshot::nsHttpMoonshot()
{
   NS_INIT_ISUPPORTS();

#if defined(PR_LOGGING)
   if (!gNegotiateLog)
      gNegotiateLog = PR_NewLogModule("moonshot");
#endif /* PR_LOGGING */

}

nsHttpMoonshot::~nsHttpMoonshot()
{
}

NS_IMETHODIMP
nsHttpMoonshot::GetAuthFlags(PRUint32 *flags)
{
  *flags = REQUEST_BASED; 
  return NS_OK;
}

NS_IMETHODIMP
nsHttpMoonshot::ChallengeReceived(nsIHttpChannel *httpChannel,
                                   const char *challenge,
                                   PRBool isProxyAuth,
                                   nsISupports **sessionState,
                                   nsISupports **continuationState,
                                   PRBool *identityInvalid)
{
    nsMoonshotSessionState *session = (nsMoonshotSessionState *) *sessionState;

    //
    // Use this opportunity to instantiate the session object
    // that gets used later when we generate the credentials.
    //
    if (!session) {
	session = new nsMoonshotSessionState();
	if (!session)
		return(NS_ERROR_OUT_OF_MEMORY);
	NS_ADDREF(*sessionState = session);
	*identityInvalid = PR_TRUE;
	LOG(("nsHttpMoonshot::A new session context established\n"));
    } else {
	LOG(("nsHttpMoonshot::Still using context from previous request\n"));
        *identityInvalid = PR_FALSE;
    }

    return NS_OK;
}

#if 0
NS_IMPL_ISUPPORTS2(nsHttpMoonshot, nsIHttpAuthenticator,
                                    nsIHttpAuthenticator_1_9_2)
#else
NS_IMPL_ISUPPORTS1(nsHttpMoonshot, nsIHttpAuthenticator)
#endif

//
// Generate proper GSSAPI error messages from the major and
// minor status codes.
//
void
nsHttpMoonshot::LogGssError(OM_uint32 maj_stat, OM_uint32 min_stat, char *prefix)
{
   OM_uint32 new_stat;
   OM_uint32 msg_ctx = 0;
   gss_buffer_desc status1_string;
   gss_buffer_desc status2_string;
   OM_uint32 ret;
   nsCAutoString error(prefix);

   error += ": ";
   do {
      ret = gss_display_status (&new_stat,
                               maj_stat,
                               GSS_C_GSS_CODE,
                               GSS_C_NULL_OID,
                               &msg_ctx,
                               &status1_string);
      error += (char *)status1_string.value;
      error += "\n";
      ret = gss_display_status (&new_stat,
                               min_stat,
                               GSS_C_MECH_CODE,
                               GSS_C_NULL_OID,
                               &msg_ctx,
                               &status2_string);
      error += (char *)status2_string.value;
      error += "\n";

   } while (!GSS_ERROR(ret) && msg_ctx != 0);

   // LOG(("%s", ToNewCString(error)));
   LOG(("%s\n", error.get()));
}

//
// GenerateCredentials
//
// This routine is responsible for creating the correct authentication
// blob to pass to the server that requested "Negotiate" authentication.
//
NS_IMETHODIMP
nsHttpMoonshot::GenerateCredentials(nsIHttpChannel *httpChannel,
                                     const char *challenge,
                                     PRBool isProxyAuth,
                                     const PRUnichar *domain,
                                     const PRUnichar *user,
                                     const PRUnichar *password,
                                     nsISupports **sessionState,
                                     nsISupports **continuationState,
                                     char **creds)
{
    LOG(("nsHttpMoonshot::GenerateCredentials [challenge=%s]\n", challenge));

    PRUint32 unused;
    return GenerateCredentials_1_9_2(httpChannel,
                                     challenge,
                                     isProxyAuth,
                                     domain,
                                     user,
                                     password,
                                     sessionState,
                                     continuationState,
                                     &unused,
                                     creds);
}

NS_IMETHODIMP
nsHttpMoonshot::GenerateCredentials_1_9_2(nsIHttpChannel *httpChannel,
                                               const char *challenge,
                                               PRBool isProxyAuth,
                                               const PRUnichar *domain,
                                               const PRUnichar *username,
                                               const PRUnichar *password,
                                               nsISupports **sessionState,
                                               nsISupports **continuationState,
                                               PRUint32 *flags,
                                               char **creds)
{
   OM_uint32 major_status, minor_status;
   gss_buffer_desc input_token = GSS_C_EMPTY_BUFFER;
   gss_buffer_desc output_token = GSS_C_EMPTY_BUFFER;
   gss_buffer_t  in_token_ptr = GSS_C_NO_BUFFER;
   gss_name_t server;
   nsMoonshotSessionState *session = (nsMoonshotSessionState *) *sessionState;


   nsCOMPtr<nsIURI> uri;
   nsresult rv;
   nsCAutoString service;
   
   LOG(("nsHttpMoonshot::GenerateCredentials() [challenge=%s]\n", challenge));

   NS_ENSURE_ARG_POINTER(creds);

   PRBool isGssapiAuth = !PL_strncasecmp(challenge, NEGOTIATE_AUTH,
		strlen(NEGOTIATE_AUTH));
   NS_ENSURE_TRUE(isGssapiAuth, NS_ERROR_UNEXPECTED);

   rv = httpChannel->GetURI(getter_AddRefs(uri));
   if (NS_FAILED(rv)) return rv;

   rv = uri->GetAsciiHost(service);
   if (NS_FAILED(rv)) return rv;
   
   LOG(("nsHttpMoonshot::GenerateCredentials() : hostname = %s\n", 
       service.get()));

  // TEST
//   LOG(("nsHttpMoonshot::Count [count=%d]\n", session->GetCount()));

   //
   // The correct service name for IIS servers is "HTTP/f.q.d.n", so
   // construct the proper service name for passing to "gss_import_name".
   //
   // TODO: Possibly make this a configurable service name for use
   // with non-standard servers that use stuff like "khttp/f.q.d.n" 
   // instead.
   //
/* DK:   service.Insert(NS_LITERAL_CSTRING("HTTP@"), 0); */
#if 0
   service.Insert("HTTP@", 0);
#else
   service.Insert("host@", 0);
#endif

   input_token.value = (void *)service.get();
   input_token.length = service.Length() + 1;

   major_status = gss_import_name(&minor_status,
                                 &input_token,
#ifdef HAVE_GSS_C_NT_HOSTBASED_SERVICE
                                 GSS_C_NT_HOSTBASED_SERVICE,
#else
				 gss_nt_service_name,
#endif
                                 &server);
   input_token.value = NULL;
   input_token.length = 0;
   if (GSS_ERROR(major_status)) {
      LogGssError(major_status, minor_status, "gss_import_name() failed");
      return NS_ERROR_FAILURE;
   }

   //
   // If the "Negotiate:" header had some data associated with it,
   // that data should be used as the input to this call.  This may
   // be a continuation of an earlier call because GSSAPI authentication
   // often takes multiple round-trips to complete depending on the
   // context flags given.  We want to use MUTUAL_AUTHENTICATION which
   // generally *does* require multiple round-trips.  Don't assume
   // auth can be completed in just 1 call.
   //
   unsigned int len = strlen(challenge);

   if (len > strlen(NEGOTIATE_AUTH)) {
	challenge += strlen(NEGOTIATE_AUTH);
	while (*challenge == ' ') challenge++;
	len = strlen(challenge);


	if(len && (0 == (len & 3)) )
	{
         if( (char)'=' == challenge[len-1] )
         {
             if( (char)'=' == challenge[len-2] )
             {
                 len -= 2;
             }
             else
             {
                 len -= 1;
             }
         }
     }


	input_token.length = (len / 4) * 3 + ((len % 4) * 3) / 4;
//        input_token.length = (len * 3)/4;
	input_token.value = malloc(input_token.length + 1);
	if (!input_token.value)
		return (NS_ERROR_OUT_OF_MEMORY);

	//
	// Decode the response that followed the "Negotiate" token
	//
	if (PL_Base64Decode(challenge, len, (char *) input_token.value) == NULL) {
		free(input_token.value);
		return(NS_ERROR_UNEXPECTED);
	}
	in_token_ptr = &input_token;
	LOG(("nsHttpMoonshot::GenerateCredentials() : Received GSS token of length %d\n", input_token.length));
   } else {
	//
	// Starting over, clear out any existing context and don't
	// use an input token.
	//
	// TEST
/*	if (session->context_state == 2) {
	  *creds = (char *) malloc (strlen(NEGOTIATE_AUTH) + 1);
	  if (!(*creds)) {
	      return NS_ERROR_OUT_OF_MEMORY;
	  }

	  sprintf(*creds, "%s", NEGOTIATE_AUTH);
	  return NS_OK;
	} else { */
	  session->Reset();
	  in_token_ptr = GSS_C_NO_BUFFER;
        //}
   }

   if (session->gss_cred == GSS_C_NO_CREDENTIAL)
   {
	OM_uint32 maj_stat, min_stat;
	gss_buffer_desc tmp_token;
	gss_name_t gss_username = GSS_C_NO_NAME;
	gss_OID_set_desc mechs, *mechsp = GSS_C_NO_OID_SET;
	const char *p, *u;

	u = strdup(NS_LossyConvertUTF16toASCII(username).get());
	p = strdup(NS_LossyConvertUTF16toASCII(password).get());

	tmp_token.value = (void *) u;
	tmp_token.length = strlen((const char *)tmp_token.value);
	maj_stat = gss_import_name(&min_stat, &tmp_token,
				   GSS_C_NT_USER_NAME,
				   &gss_username);

	if (GSS_ERROR(maj_stat)) {
	    LogGssError(maj_stat, min_stat, "gss_import_name() failed");
            session->Reset();
            return NS_ERROR_FAILURE;
	}

	mechs.elements = GetOID();
	mechs.count = 1;
	mechsp = &mechs;

	tmp_token.value = (void *) p;
	tmp_token.length = strlen(p);//strlen((const char*)tmp_token.value);
	maj_stat = gss_acquire_cred_with_password(&min_stat,
						  gss_username, &tmp_token, 0,
						  mechsp, GSS_C_INITIATE,
						  &session->gss_cred, NULL, NULL);
	if (GSS_ERROR(maj_stat)) {
	    LogGssError(maj_stat, min_stat, "gss_acquire_cred_with_password()");
	    session->Reset();
	    return NS_ERROR_FAILURE;
	}

	LOG(("Acquired credential for user '%s' using password '%s'\n",
	     u, p));
   }

   major_status = gss_init_sec_context(&minor_status,
				    session->gss_cred,
				    &session->gss_ctx,
				    server,
				    GetOID(),
				    GSS_C_MUTUAL_FLAG,
				    /* GSS_C_INDEFINITE */ 0,
				    GSS_C_NO_CHANNEL_BINDINGS,
				    in_token_ptr,
				    nsnull,
				    &output_token,
				    nsnull,
				    nsnull);

   if (GSS_ERROR(major_status)) {
      LogGssError(major_status, minor_status, "gss_init_sec_context() failed");
      (void) gss_release_name(&minor_status, &server);
//      gss_release_cred(&minor_status, &cred);
      session->Reset();
      if (input_token.length > 0 && input_token.value != NULL)
	      (void) gss_release_buffer(&minor_status, &input_token);
      return NS_ERROR_FAILURE;
   }

   if (major_status == GSS_S_COMPLETE) {
	//
	// We are done with this authentication, reset the context. 
	//
	// TEST
	// session->Reset();
	session->gss_state = GSS_CTX_ESTABLISHED;
	LOG(("GSS Auth done"));
   } else if (major_status == GSS_S_CONTINUE_NEEDED) {
	//
	// We could create a continuation state, but its not
	// really necessary.
	//
	// The important thing is that we do NOT reset the
	// session context here because it will be needed on the
	// next call.
	//
	// TEST
	session->gss_state = GSS_CTX_IN_PROGRESS;
	LOG(("GSS Auth continuing"));
   } 

   // We don't need the input token data anymore.
   if (input_token.length > 0 && input_token.value != NULL)
	(void) gss_release_buffer(&minor_status, &input_token);

   if (output_token.length == 0) {
      LOG(("No GSS output token to send, exiting"));
      (void) gss_release_name(&minor_status, &server);
//      gss_release_cred(&minor_status, &cred);
      return NS_ERROR_FAILURE;
   }

   //
   // The token output from the gss_init_sec_context call is
   // encoded and used as the Authentication response for the
   // server.
   //
   char *encoded_token = PL_Base64Encode((char *)output_token.value,
                                        output_token.length,
                                        nsnull);
   if (!encoded_token) {
      (void) gss_release_buffer(&minor_status, &output_token);
      (void) gss_release_name(&minor_status, &server);
//      gss_release_cred(&minor_status, &cred);
      return NS_ERROR_OUT_OF_MEMORY;
   }

   LOG(("Sending a token of length %d\n", output_token.length));

   // allocate a buffer sizeof("Negotiate" + " " + b64output_token + "\0")
   *creds = (char *) malloc (strlen(NEGOTIATE_AUTH) + 1 + strlen(encoded_token) + 1);
   if (!(*creds)) {
      PR_Free(encoded_token);
      (void) gss_release_buffer(&minor_status, &output_token);
      (void) gss_release_name(&minor_status, &server);
//      gss_release_cred(&minor_status, &cred);
      return NS_ERROR_OUT_OF_MEMORY;
   }

   sprintf(*creds, "%s %s", NEGOTIATE_AUTH, encoded_token);
   PR_Free(encoded_token);

   (void) gss_release_buffer(&minor_status, &output_token);
   (void) gss_release_name(&minor_status, &server);
//      gss_release_cred(&minor_status, &cred);

   LOG(("returning the call"));

   return NS_OK;
}
