#ifndef _nsMoonshotSessionState_h__
#define _nsMoonshotSessionState_h__

#include <gssapi.h>

class nsMoonshotSessionState : public nsISupports
{
    public:
	NS_DECL_ISUPPORTS;

	nsMoonshotSessionState();
	virtual ~nsMoonshotSessionState();
	NS_IMETHOD Reset();

	enum {
	    GSS_CTX_EMPTY,
	    GSS_CTX_IN_PROGRESS,
	    GSS_CTX_ESTABLISHED
	} gss_state;

	gss_cred_id_t gss_cred;

    private:
}

#endif
