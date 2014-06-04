package com.identityblitz.saml.action

import com.identityblitz.saml.ws.transport.{PlayResponseAdapter, PlayRequestAdapter}
import play.api.mvc.Request
import edu.internet2.middleware.shibboleth.idp.session.Session
import org.opensaml.ws.transport.http.HTTPTransportUtils
import org.opensaml.xml.util.Base64
import org.joda.time.DateTime
import com.identityblitz.saml.IdpPlayBridge.{samlCtx, logger}
import edu.internet2.middleware.shibboleth.common.session.SessionManager
import java.security.{GeneralSecurityException, MessageDigest}

/**
 */
trait SessionBridge {

  /** Name of the IdP Cookie containing the IdP session ID. */
  protected val IDP_SESSION_COOKIE_NAME = "_idp_session"

  /** Whether the client must always come back from the same address. */
  protected val ensureConsistentClientAddress = false

  private lazy val sessionManager = samlCtx.getBean("shibboleth.SessionManager").asInstanceOf[SessionManager[Session]]

  protected def createIdpSession(implicit inTr: PlayRequestAdapter, outTr: PlayResponseAdapter, request: Request[_]) = {
    val idpSession = sessionManager.createSession()
    inTr.setAttribute(Session.HTTP_SESSION_BINDING_ATTRIBUTE, idpSession)
    outTr.addCookie(IDP_SESSION_COOKIE_NAME, createSessionCookieValue(idpSession))
    idpSession
  }

  protected def getIdpSession(implicit request: Request[_]) = request.cookies.get(IDP_SESSION_COOKIE_NAME)
    .filter(!_.value.trim.isEmpty)
    .map(sc => HTTPTransportUtils.urlDecode(sc.value))
    .map(_.split("\\|"))
    .filter(_.length == 3)
    .flatMap(vc => {
    val sessionIdBytes = Base64.decode(vc(1))
    val sessionId = new String(sessionIdBytes)
    Option(sessionManager.getSession(sessionId)).orElse{
      logger.debug("No session associated with session ID {} - session must have timed out", sessionId)
      None
    }.filter(s => {
      isCookieValid(remoteAddressBytes = Base64.decode(vc(0)), sessionIdBytes,
        signatureBytes = Base64.decode(vc(2)), s.getSessionSecret)
    }).map{s =>
      logger.trace("Updating IdP session activity time and adding session object to the request")
      s.setLastActivityInstant(new DateTime())
      s
    }
  })

  //todo: rewrite
  private def isCookieValid(remoteAddressBytes: Array[Byte], sessionIdBytes: Array[Byte], signatureBytes: Array[Byte],
                            sessionSecret: Array[Byte])(implicit request: Request[_]): Boolean = {

    if (ensureConsistentClientAddress) {
      val remoteAddress = new String(remoteAddressBytes)
      if (request.remoteAddress == remoteAddress) {
        /*        logger.error("Client sent a cookie from address {} but the cookie was issued to address {}",
                  request.remoteAddress, remoteAddress)*/
        return false
      }
    }

    try {
      val digester = MessageDigest.getInstance("SHA")
      digester.update(sessionSecret)
      digester.update(remoteAddressBytes)
      digester.update(sessionIdBytes)
      if (!java.util.Arrays.equals(digester.digest, signatureBytes)) {
        logger.error("Session cookie has been tampered with, its signature no longer matches expected value")
        false
      } else {
        true
      }
    }
    catch {
      case e: GeneralSecurityException =>
        logger.error("Unable to compute signature over session cookie material", e)
        false
    }
  }

  protected def createSessionCookieValue(userSession: Session)(implicit request: Request[_]) = {
    val remoteAddress: Array[Byte] = request.remoteAddress.getBytes
    val sessionId: Array[Byte] = userSession.getSessionID.getBytes

    val digester = MessageDigest.getInstance("SHA")
    digester.update(userSession.getSessionSecret)
    digester.update(remoteAddress)
    digester.update(sessionId)
    val signature = Base64.encodeBytes(digester.digest)

    new StringBuilder()
      .append(Base64.encodeBytes(remoteAddress, Base64.DONT_BREAK_LINES)).append("|")
      .append(Base64.encodeBytes(sessionId, Base64.DONT_BREAK_LINES)).append("|")
      .append(signature)
      .toString()

  }

}
