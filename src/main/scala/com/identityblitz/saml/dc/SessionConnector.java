package com.identityblitz.saml.dc;

import edu.internet2.middleware.shibboleth.common.attribute.BaseAttribute;
import edu.internet2.middleware.shibboleth.common.attribute.resolver.AttributeResolutionException;
import edu.internet2.middleware.shibboleth.common.attribute.resolver.provider.ShibbolethResolutionContext;
import edu.internet2.middleware.shibboleth.common.attribute.resolver.provider.dataConnector.BaseDataConnector;

import java.util.Map;


/**
 */
public class SessionConnector extends BaseDataConnector {

    @Override
    @SuppressWarnings("unchecked")
    public Map<String, BaseAttribute> resolve(ShibbolethResolutionContext ctx) throws AttributeResolutionException {
        final Object mapObj = SessionConnectorHelper$.MODULE$.resolve(ctx);
        return (Map<String, BaseAttribute>)mapObj;
    }

    @Override
    public void validate() throws AttributeResolutionException {

    }
}
