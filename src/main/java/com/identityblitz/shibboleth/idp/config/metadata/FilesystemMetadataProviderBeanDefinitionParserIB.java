/*
 * Licensed to the University Corporation for Advanced Internet Development, 
 * Inc. (UCAID) under one or more contributor license agreements.  See the 
 * NOTICE file distributed with this work for additional information regarding
 * copyright ownership. The UCAID licenses this file to You under the Apache 
 * License, Version 2.0 (the "License"); you may not use this file except in 
 * compliance with the License.  You may obtain a copy of the License at
 *
 *    http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package com.identityblitz.shibboleth.idp.config.metadata;

import com.identityblitz.saml.SubstitutionResolver;
import edu.internet2.middleware.shibboleth.common.config.metadata.AbstractReloadingMetadataProviderBeanDefinitionParser;
import org.opensaml.saml2.metadata.provider.FilesystemMetadataProvider;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.support.BeanDefinitionBuilder;
import org.springframework.beans.factory.xml.ParserContext;
import org.w3c.dom.Element;

import javax.xml.namespace.QName;
import java.io.File;

/**
 * Spring bean definition parser for Shibboleth file system based metadata provider definition.
 */
public class FilesystemMetadataProviderBeanDefinitionParserIB extends AbstractReloadingMetadataProviderBeanDefinitionParser {

    /** Schema type name. */
    public static final QName TYPE_NAME = new QName(MetadataNamespaceHandlerIB.NAMESPACE, "FilesystemMetadataProvider");

    /** Class logger. */
    private Logger log = LoggerFactory.getLogger(FilesystemMetadataProviderBeanDefinitionParserIB.class);

    /** {@inheritDoc} */
    protected Class getBeanClass(Element element) {
        return FilesystemMetadataProvider.class;
    }

    /** {@inheritDoc} */
    protected void doParse(Element config, ParserContext parserContext, BeanDefinitionBuilder builder) {
        super.doParse(config, parserContext, builder);

        String metadataFile = SubstitutionResolver.resolve(config.getAttributeNS(null, "metadataFile"));
        log.debug("Metadata provider '{}' reading metadata from: {}", getProviderId(config), metadataFile);
        builder.addConstructorArgValue(new File(metadataFile));
    }
}