#ifndef _nsMoonshotSessionState_h__
#define _nsMoonshotSessionState_h__

#include <nsISupportsUtils.h>
#include <gssapi.h>

typedef enum {
    GSS_CTX_EMPTY,
    GSS_CTX_IN_PROGRESS,
    GSS_CTX_ESTABLISHED
} gss_state_t;

class NS_EXPORT
nsMoonshotSessionState : public nsISupports
{
    public:
	NS_DECL_ISUPPORTS

	nsMoonshotSessionState() {
	    gss_ctx = GSS_C_NO_CONTEXT;
	    gss_state = GSS_CTX_EMPTY;
	    gss_cred = GSS_C_NO_CREDENTIAL;
	}

	virtual ~nsMoonshotSessionState() {
	    OM_uint32 min_stat;

	    if (gss_ctx != GSS_C_NO_CONTEXT)
		gss_delete_sec_context(&min_stat, &gss_ctx, GSS_C_NO_BUFFER);
	    if (gss_cred != GSS_C_NO_CREDENTIAL)
		gss_release_cred(&min_stat, &gss_cred);
	    gss_ctx = GSS_C_NO_CONTEXT;
	    gss_cred = GSS_C_NO_CREDENTIAL;
	    gss_state = GSS_CTX_EMPTY;
	}

	void Reset();

	gss_state_t gss_state;
	gss_cred_id_t gss_cred;
	gss_ctx_id_t gss_ctx;
};

#endif
