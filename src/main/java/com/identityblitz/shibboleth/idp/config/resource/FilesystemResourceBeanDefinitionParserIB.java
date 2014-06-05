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

package com.identityblitz.shibboleth.idp.config.resource;

import com.identityblitz.saml.SubstitutionResolver;
import edu.internet2.middleware.shibboleth.common.config.resource.AbstractResourceBeanDefinitionParser;
import org.opensaml.util.resource.FilesystemResource;
import org.opensaml.xml.util.DatatypeHelper;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.BeanCreationException;
import org.springframework.beans.factory.support.AbstractBeanDefinition;
import org.springframework.beans.factory.support.BeanDefinitionBuilder;
import org.springframework.beans.factory.xml.ParserContext;
import org.w3c.dom.Element;

import javax.xml.namespace.QName;
import java.net.URI;
import java.net.URISyntaxException;

/** Bean definition parser for {@link org.opensaml.util.resource.FilesystemResource}s. */
public class FilesystemResourceBeanDefinitionParserIB extends AbstractResourceBeanDefinitionParser {

    /** Schema type. */
    public static final QName SCHEMA_TYPE = new QName(ResourceNamespaceHandlerIB.NAMESPACE, "FilesystemResource");
    
    /** Class logger. */
    private final Logger log = LoggerFactory.getLogger(FilesystemResourceBeanDefinitionParserIB.class);

    /** {@inheritDoc} */
    protected Class getBeanClass(Element arg0) {
        return FilesystemResource.class;
    }

    /** {@inheritDoc} */
    protected String resolveId(Element configElement, AbstractBeanDefinition beanDefinition, ParserContext parserContext) {
        return FilesystemResource.class.getName() + ":"
                + SubstitutionResolver.resolve(DatatypeHelper.safeTrimOrNullString(configElement.getAttributeNS(null, "file")));
    }

    /** {@inheritDoc} */
    protected void doParse(Element element, ParserContext parserContext, BeanDefinitionBuilder builder) {

        String file = SubstitutionResolver.resolve(DatatypeHelper.safeTrimOrNullString(element.getAttributeNS(null, "file")));
        if(file.startsWith("file:")){
            try{
                builder.addConstructorArgValue(new URI(file));
            }catch(URISyntaxException e){
                log.error("Illegal file: URI syntax", e);
                throw new BeanCreationException("Illegal file: URI syntax");
            }
        }else{
            builder.addConstructorArgValue(file);
        }
        
        addResourceFilter(element, parserContext, builder);
    }
}