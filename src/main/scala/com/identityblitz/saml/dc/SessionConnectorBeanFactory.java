package com.identityblitz.saml.dc;

import edu.internet2.middleware.shibboleth.common.config.attribute.resolver.dataConnector.BaseDataConnectorFactoryBean;

/**
 */
public class SessionConnectorBeanFactory extends BaseDataConnectorFactoryBean {

    @Override
    public Class getObjectType() {
        return SessionConnector.class;
    }

    @Override
    protected Object createInstance() throws Exception {
        SessionConnector connector = new SessionConnector();
        populateDataConnector(connector);

        return connector;
    }
}
