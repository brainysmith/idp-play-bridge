package com.identityblitz.saml.dc;

import edu.internet2.middleware.shibboleth.common.config.BaseSpringNamespaceHandler;

/**
  */
public class AttributeResolverNamespaceHandler extends BaseSpringNamespaceHandler {

    public static final String NAMESPACE = "urn:identityblitz:shibboleth:2.0:resolver:ar";


    @Override
    public void init() {
        registerBeanDefinitionParser(SessionConnectorBeanDefinitionParser.TYPE_NAME,
                new SessionConnectorBeanDefinitionParser());
    }
}
