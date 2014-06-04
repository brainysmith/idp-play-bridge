package com.identityblitz.saml.dc;

import edu.internet2.middleware.shibboleth.common.config.attribute.resolver.dataConnector.BaseDataConnectorBeanDefinitionParser;
import org.w3c.dom.Element;

import javax.xml.namespace.QName;

/**
 */
class SessionConnectorBeanDefinitionParser extends BaseDataConnectorBeanDefinitionParser {

    public static final QName TYPE_NAME = new QName(AttributeResolverNamespaceHandler.NAMESPACE, "SessionConnector");

    /** Local name of attribute. */
  /*val ATTRIBUTE_ELEMENT_NAME: QName = new QName(DataConnectorNamespaceHandler.NAMESPACE, "Attribute")*/

    @Override
    protected Class getBeanClass(Element element) {
        return SessionConnectorBeanFactory.class;
    }

}
