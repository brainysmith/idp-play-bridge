package com.identityblitz.saml.ws.transport

import java.util
import org.opensaml.ws.transport.http.HTTPTransport.HTTP_VERSION
import org.opensaml.xml.security.credential.Credential
import java.io.{ByteArrayInputStream, InputStream}
import play.api.mvc.{RawBuffer, Request}
import scala.collection.JavaConversions._
import com.identityblitz.shibboleth.idp.saml.ws.transposrt.HTTPInTransportWithQueryString

/**
 */
class PlayRequestAdapter(private val request: Request[RawBuffer],
                         private val _attributes: Map[String, AnyRef]) extends HTTPInTransportWithQueryString {

  /** Whether the peer endpoint has been authenticated. */
  private var peerAuthenticated: Boolean = false

  private val attributes = scala.collection.mutable.Map[String, AnyRef](_attributes.toSeq: _*)

  override def getPeerDomainName: String = request.remoteAddress

  override def getPeerAddress: String = request.remoteAddress

  override def getIncomingStream: InputStream = new ByteArrayInputStream(request.body.asBytes().getOrElse(Array()))

  override def isIntegrityProtected: Boolean = request.uri.startsWith("https")

  override def isConfidential: Boolean = request.uri.startsWith("https")

  override def setAuthenticated(isAuthenticated: Boolean): Unit = peerAuthenticated = isAuthenticated

  override def isAuthenticated: Boolean = peerAuthenticated

  override def getCharacterEncoding: String = request.charset.getOrElse(null)

  override val getVersion: HTTP_VERSION = null

  override def getParameterValues(name: String): util.List[String] = request.queryString.get(name).getOrElse(Seq()).toList

  override def getParameterValue(name: String): String = request.queryString.get(name).map(_.head).getOrElse(null)

  override def getHTTPMethod: String = request.method

  override def getHeaderValue(name: String): String = request.headers.get(name).getOrElse(null)

  override def getPeerCredential: Credential = null

  override def getAttribute(name: String): AnyRef = attributes.getOrElse(name, null)

  /**
   * This method is not supported for this transport implementation.
   */
  override def setIntegrityProtected(isIntegrityProtected: Boolean): Unit = {}

  /**
   * This method is not supported for this transport implementation.
   */
  override def setConfidential(isConfidential: Boolean): Unit = {}

  /**
   * This method is not supported for this transport implementation.It always returns - 1;
   **/
  override val getStatusCode: Int = -1

  /**
   * This method is not supported for this transport implementation.
   */
  override def getLocalCredential: Credential = null

  override def getCookie (name: String): String = request.cookies.get(name).map(_.value).getOrElse(null)

  def setAttribute(name: String, value: AnyRef): Unit = attributes += (name -> value)

  override def getQueryString: String = request.rawQueryString
}
