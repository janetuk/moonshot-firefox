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

#include "nsISupportsUtils.h"
#include "nsIGenericFactory.h"

#include "nsHttpMoonshot.h"

// macro expansion defines our factory constructor method
// used by the components[] array below.
NS_GENERIC_FACTORY_CONSTRUCTOR(nsHttpMoonshot)

static nsModuleComponentInfo components[] = {
  { "HTTP Moonshot Auth Encoder", 
    NS_HTTPMOONSHOT_CID,
    NS_HTTP_AUTHENTICATOR_CONTRACTID,
    nsHttpMoonshotConstructor,
  },
};

NS_IMPL_NSGETMODULE(nsHttpMoonshotModule, components)
