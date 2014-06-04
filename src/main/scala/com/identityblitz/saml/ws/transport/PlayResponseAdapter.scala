package com.identityblitz.saml.ws.transport

import org.opensaml.xml.security.credential.Credential
import java.io.{ByteArrayOutputStream, OutputStream}
import java.util
import org.opensaml.ws.transport.http.HTTPTransport.HTTP_VERSION
import play.api.mvc._
import play.api.mvc.Results._
import PlayResponseAdapter._
import com.identityblitz.shibboleth.idp.saml.ws.transposrt.HTTPOutTransportWithCookie
import play.api.mvc.DiscardingCookie
import play.api.mvc.RawBuffer
import play.api.mvc.Cookie
import scala.Some
import scala.concurrent.{ExecutionContext, Future}
import java.net.{MalformedURLException, URL}
import scala.util.Try
import com.identityblitz.saml.action.Saml
import com.identityblitz.saml.IdpPlayBridge.contextPath

/**
  */
class PlayResponseAdapter(private val inTr: PlayRequestAdapter,
                          private val request: Request[RawBuffer]) extends HTTPOutTransportWithCookie {

  private val secure: Boolean = request.uri.startsWith("https")
  private var peerAuthenticated: Boolean = false
  private var redirectLocation: Option[String] = None
  private var statusCode: Option[Int] = None
  private val headers = scala.collection.mutable.Map[String,String]()
  private var characterEncoding: Option[String] = None
  private val outputStream = new ByteArrayOutputStream(65536)
  private val cookiesToAdd = scala.collection.mutable.Buffer[Cookie]()
  private val cookiesToDiscard = scala.collection.mutable.Buffer[DiscardingCookie]()
  private val attributes = scala.collection.mutable.Map[String, AnyRef]()

  private val directCalls = Map[String, (PlayRequestAdapter, PlayResponseAdapter) => Action[_]](
    (contextPath + "/AuthnEngine") -> ((inTr, outTr) => Saml.startLogin(inTr, outTr)),
    "/SLOServlet" -> ((inTr, outTr) => Saml.startLogout(inTr, outTr))
  )

  override def sendRedirect(location: String): Unit = redirectLocation = Some(location)

  override def setStatusCode(code: Int): Unit = statusCode = Some(code)

  override def addParameter(name: String, value: String): Unit = {}

  override def setHeader(name: String, value: String): Unit = headers += name -> value

  override def setVersion(version: HTTP_VERSION): Unit = {}

  override def setIntegrityProtected(isIntegrityProtected: Boolean): Unit = {}

  override def isIntegrityProtected: Boolean = secure

  override def setConfidential(isConfidential: Boolean): Unit = {}

  override def isConfidential: Boolean = secure

  override def setAuthenticated(isAuthenticated: Boolean): Unit = peerAuthenticated = isAuthenticated

  override def isAuthenticated: Boolean = isAuthenticated

  override def getLocalCredential: Credential = null

  override def getCharacterEncoding: String = characterEncoding.getOrElse(null)

  override def setCharacterEncoding(encoding: String): Unit = characterEncoding = Some(encoding)

  override def getAttribute(name: String): AnyRef = attributes.getOrElse(name, null)

  override def getVersion: HTTP_VERSION = null

  override def getParameterValues(name: String): util.List[String] = null

  override def getParameterValue(name: String): String = null

  override def getStatusCode: Int = -1

  override def getHTTPMethod: String = null

  override def getHeaderValue(name: String): String = null

  override def getOutgoingStream: OutputStream = outputStream

  override def setAttribute(name: String, value: AnyRef): Unit = attributes += (name -> value)

  override def getPeerCredential: Credential = null

  /*todo: set secure true*/
  override def addCookie(name: String, value: String): Unit = {
    cookiesToAdd += Cookie(name, value, maxAge = None, path = "/blitz", domain = None, secure = false, httpOnly = true)
  }

  override def discardCookie(name: String): Unit = {
    cookiesToDiscard += DiscardingCookie(name, path = "/blitz", domain = None, secure = false)
  }

  def cookies = cookiesToAdd.toSeq

  def discardCookies = cookiesToDiscard.toSeq

  def result = {
    import ExecutionContext.Implicits.global
    redirectLocation.fold {
      characterEncoding foreach (encoding =>
        headers.get(CONTENT_TYPE_HEADER_NAME) foreach (ct => {
          headers += CONTENT_TYPE_HEADER_NAME -> (ct + "; " + encoding)
        }))
      Future.successful(Status(statusCode.getOrElse(200))
        .apply(outputStream.toByteArray)
        .withHeaders(headers.toSeq: _*))
    }(location =>
      directCalls.get(
        Try(new URL(location).getPath).recover{case e: MalformedURLException => location}.get
    ).fold(Future.successful(Redirect(location)))(action => {
      action(inTr, this).apply(request).run
    }))
      .map(_.withCookies(cookiesToAdd: _*).discardingCookies(cookiesToDiscard: _*))
  }

}

object PlayResponseAdapter {

  val CONTENT_TYPE_HEADER_NAME = "Content-Type"

}
