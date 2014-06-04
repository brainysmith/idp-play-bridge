package com.identityblitz.saml.action

import com.identityblitz.saml.ws.transport.{PlayResponseAdapter, PlayRequestAdapter}
import com.identityblitz.shibboleth.idp.util.HttpHelper
import com.identityblitz.saml.IdpPlayBridge._
import org.opensaml.util.storage.StorageService
import edu.internet2.middleware.shibboleth.idp.authn.LoginContextEntry

/**
 */
trait LoginContextBridge {

  private lazy val storageService = samlCtx.getBean("shibboleth.StorageService").asInstanceOf[StorageService[String, LoginContextEntry]]

  protected def getIdpLoginContext(implicit inTr: PlayRequestAdapter, outTr: PlayResponseAdapter) = {
    HttpHelper.getLoginContext(storageService, inTr, outTr)
  }

}
