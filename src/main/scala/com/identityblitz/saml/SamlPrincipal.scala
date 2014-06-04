package com.identityblitz.saml

import com.identityblitz.json.JVal
import edu.internet2.middleware.shibboleth.idp.authn.UsernamePrincipal
import IdpPlayBridge.{logger, claimOfPrincipalName}

/**
  */
case class SamlPrincipal(claims: JVal) extends UsernamePrincipal(
  (claims \ claimOfPrincipalName).asOpt[String].getOrElse{
    val err = s"Can't create blitz principal. The specified claims [${claims.toJson}] doesn't contain the mandatory " +
      s"claim with '$claimOfPrincipalName' key"
    logger.error(err)
    throw new IllegalArgumentException(err)
  }) {

  override def toString: String = new StringBuilder("BlitzPrincipal(name=").append(getName)
    .append(",claims=").append(claims.toJson).append(")").toString()
}
