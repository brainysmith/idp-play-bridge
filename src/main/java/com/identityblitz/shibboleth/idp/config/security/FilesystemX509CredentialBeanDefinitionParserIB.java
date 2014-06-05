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

package com.identityblitz.shibboleth.idp.config.security;

import com.identityblitz.saml.SubstitutionResolver;
import edu.internet2.middleware.shibboleth.common.config.security.AbstractX509CredentialBeanDefinitionParser;
import org.springframework.beans.FatalBeanException;

import javax.xml.namespace.QName;
import java.io.FileInputStream;
import java.io.IOException;

/**
 * Spring bean definition parser for filesytem-based credential configuration elements.
 */
public class FilesystemX509CredentialBeanDefinitionParserIB extends AbstractX509CredentialBeanDefinitionParser {

    /** Schema type. */
    public static final QName SCHEMA_TYPE = new QName(SecurityNamespaceHandlerIB.NAMESPACE, "X509Filesystem");

    /** {@inheritDoc} */
    protected byte[] getEncodedCRL(String certCRLContent) {
        try {
            FileInputStream ins = new FileInputStream(SubstitutionResolver.resolve(certCRLContent));
            byte[] encoded = new byte[ins.available()];
            ins.read(encoded);
            return encoded;
        } catch (IOException e) {
            throw new FatalBeanException("Unable to read CRL(s) from file " + certCRLContent, e);
        }
    }

    /** {@inheritDoc} */
    protected byte[] getEncodedCertificate(String certConfigContent) {
        try {
            FileInputStream ins = new FileInputStream(SubstitutionResolver.resolve(certConfigContent));
            byte[] encoded = new byte[ins.available()];
            ins.read(encoded);
            return encoded;
        } catch (IOException e) {
            throw new FatalBeanException("Unable to read certificate(s) from file " + certConfigContent, e);
        }
    }

    /** {@inheritDoc} */
    protected byte[] getEncodedPrivateKey(String keyConfigContent) {
        try {
            FileInputStream ins = new FileInputStream(SubstitutionResolver.resolve(keyConfigContent));
            byte[] encoded = new byte[ins.available()];
            ins.read(encoded);
            return encoded;
        } catch (IOException e) {
            throw new FatalBeanException("Unable to read private key from file " + keyConfigContent, e);
        }
    }
}