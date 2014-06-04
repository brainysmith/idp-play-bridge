package com.identityblitz.saml.dc

import edu.internet2.middleware.shibboleth.common.attribute.resolver.provider.ShibbolethResolutionContext
import com.identityblitz.json._
import scala.collection.convert.WrapAsJava._
import edu.internet2.middleware.shibboleth.common.attribute.BaseAttribute
import edu.internet2.middleware.shibboleth.common.attribute.provider.BasicAttribute
import com.identityblitz.saml.IdpPlayBridge.logger
import com.identityblitz.saml.SamlPrincipal

/**
  */
object SessionConnectorHelper {

  def resolve(resolutionContext: ShibbolethResolutionContext) = {
    val session = resolutionContext.getAttributeRequestContext.getUserSession
    val principals = session.getSubject.getPrincipals(classOf[SamlPrincipal])
    if (!principals.isEmpty) {
      val bp = principals.iterator().next()
      bp.claims match {
        case JObj(seq) =>
          if (logger.isTraceEnabled)
            logger.trace("Processing the following claims: {}", bp.claims.toJson)

          mapAsJavaMap(seq.map(t => t._1 -> (t._2 match {
            case JStr(v) => crtBA(t._1, v)
            case JNum(v) => crtBA(t._1, v)
            case JBool(v) => crtBA(t._1, v)
            case JNull | JUndef => crtBA(t._1, null)
            case _ @ u => crtBA(t._1, u.toJson)
          })).toMap[String, BaseAttribute[_]])
        case _ @ u =>
          if (logger.isDebugEnabled)
            logger.debug("Unknown type of the blitz principal's claims: {}", u)
          mapAsJavaMap(Map.empty[String, BaseAttribute[_]])
      }
    } else {
      if (logger.isDebugEnabled)
        logger.debug("Blitz principal not found against principals: {}", principals)
      mapAsJavaMap(Map.empty[String, BaseAttribute[_]])
    }
  }

  private def crtBA[T](k: String, v: T):BasicAttribute[T] = {
    val ba = new BasicAttribute[T](k)
    ba.getValues.add(v)
    ba
  }

}
