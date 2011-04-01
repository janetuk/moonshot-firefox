#include "nsMoonshotSessionState.h"

nsMoonshotSessionState::nsMoonshotSessionState()
{
    gss_ctx = GSS_C_NO_CONTEXT;
    gss_state = GSS_CTX_EMPTY;
    gss_cred = GSS_C_NO_CREDENTIAL;
}

nsMoonshotSessionState::~nsMoonshotSessionState()
{
    OM_uint32 min_stat;

    if (gss_ctx != GSS_C_NO_CONTEXT)
	gss_delete_sec_context(&min_stat, &gss_ctx, GSS_C_NO_BUFFER);

    if (gss_cred != GSS_C_NO_CREDENTIAL)
	gss_release_cred(&min_stat, &gss_cred);

    gss_ctx = GSS_C_NO_CONTEXT;
    gss_cred = GSS_C_NO_CREDENTIAL;
    gss_state = GSS_CTX_EMPTY;
}

void
nsMoonshotSessionState::Reset()
{
    OM_uint32 min_stat;

    if (gss_ctx != GSS_C_NO_CONTEXT)
	gss_delete_sec_context(&min_stat, &gss_ctx, GSS_C_NO_BUFFER);
    gss_ctx = GSS_C_NO_CONTEXT;
    gss_state = GSS_CTX_EMPTY;

    if (gss_cred != GSS_C_NO_CREDENTIAL)
	gss_release_cred(&min_stat, &gss_cred);
    gss_cred = GSS_C_NO_CREDENTIAL;
}

NS_IMPL_ISUPPORTS0(nsMoonshotSessionState)
