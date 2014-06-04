package com.identityblitz.saml

import com.identityblitz.json.JVal
import edu.internet2.middleware.shibboleth.idp.authn.UsernamePrincipal
import SamlPrincipal._
import IdpPlayBridge.logger

/**
  */
case class SamlPrincipal(claims: JVal) extends UsernamePrincipal(
  (claims \ PRINCIPAL_NAME_CLAIM_KEY).asOpt[String].getOrElse{
    val err = s"Can't create blitz principal. The specified claims [${claims.toJson}] doesn't contain the mandatory " +
      s"claim with '$PRINCIPAL_NAME_CLAIM_KEY' key"
    logger.error(err)
    throw new IllegalArgumentException(err)
  }) {

  override def toString: String = new StringBuilder("BlitzPrincipal(name=").append(getName)
    .append(",claims=").append(claims.toJson).append(")").toString()
}

object SamlPrincipal {

  /*todo: read from config*/
  val PRINCIPAL_NAME_CLAIM_KEY = "uid"

}
