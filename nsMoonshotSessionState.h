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

	nsMoonshotSessionState();
	virtual ~nsMoonshotSessionState();
	void Reset();

	gss_state_t gss_state;
	gss_cred_id_t gss_cred;
	gss_ctx_id_t gss_ctx;
};

#endif
