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
import edu.internet2.middleware.shibboleth.common.config.metadata.HTTPMetadataProviderBeanDefinitionParser;
import org.opensaml.saml2.metadata.provider.FileBackedHTTPMetadataProvider;
import org.opensaml.xml.util.DatatypeHelper;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.support.BeanDefinitionBuilder;
import org.springframework.beans.factory.xml.ParserContext;
import org.w3c.dom.Element;

import javax.xml.namespace.QName;

/** Spring bean definition for Shibboleth file backed metadata provider. */
public class FileBackedHTTPMetadataProviderBeanDefinitionParserIB extends HTTPMetadataProviderBeanDefinitionParser {

    /** Schema type name. */
    public static final QName TYPE_NAME = new QName(MetadataNamespaceHandlerIB.NAMESPACE,
            "FileBackedHTTPMetadataProvider");

    /** Class logger. */
    private Logger log = LoggerFactory.getLogger(FileBackedHTTPMetadataProviderBeanDefinitionParserIB.class);

    /** {@inheritDoc} */
    protected Class getBeanClass(Element element) {
        return FileBackedHTTPMetadataProvider.class;
    }

    /** {@inheritDoc} */
    protected void doParse(Element element, ParserContext parserContext, BeanDefinitionBuilder builder) {
        String providerId = getProviderId(element);
        
        super.doParse(element, parserContext, builder);

        String backingFile = SubstitutionResolver.resolve(DatatypeHelper.safeTrimOrNullString(element.getAttributeNS(null, "backingFile")));
        log.debug("Metadata provider '{}' backing up remote metadata file to: ", providerId, backingFile);
        builder.addConstructorArgValue(backingFile);
    }
}