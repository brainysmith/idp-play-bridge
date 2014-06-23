package com.identityblitz.saml.action

import play.api.mvc.{Request, Controller}
import com.identityblitz.saml.IdpPlayBridge.samlCtx
import edu.internet2.middleware.shibboleth.common.profile._
import edu.internet2.middleware.shibboleth.idp.session.Session
import com.identityblitz.saml.ws.transport.{PlayResponseAdapter, PlayRequestAdapter}
import java.net.URL
import play.api.Play
import scala.concurrent.Future
import org.opensaml.ws.transport.{OutTransport, InTransport}
import javax.servlet.http.{HttpSession, HttpServletResponse, Part, HttpServletRequest}
import javax.servlet._
import java.util
import java.util.Locale
import java.io.BufferedReader
import java.security.Principal
import com.identityblitz.saml.IdpPlayBridge.{logger, contextPath}
import play.api.mvc.RawBuffer
import play.api.mvc.SimpleResult
import scala.util.{Failure, Try}

/**
  */
trait HandlerBridge {
  this: Controller with SessionBridge =>

  private lazy val httpPort = Play.current.configuration.getString("http.port").map(ps => if (ps == "disabled") 0 else ps.toInt).getOrElse(9000)
  private lazy val httpsPort = Play.current.configuration.getInt("https.port").getOrElse(0)
  private lazy val handlerManager = samlCtx.getBean("shibboleth.HandlerManager").asInstanceOf[ProfileHandlerManager]

  private lazy val profileContextPath = contextPath + "/profile"

  protected def getTransports(implicit request: Request[RawBuffer]): (PlayRequestAdapter, PlayResponseAdapter) = {
    val absoluteUrl = "http" + (if (request.host.endsWith(":" + httpsPort)) "s" else "") + "://" + request.host + request.uri
    val inTr = new PlayRequestAdapter(request,
      Map("URL" -> new URL(absoluteUrl),
        "CONTEXT_PATH" -> profileContextPath,
        "REMOTE_ADDRESS" -> request.remoteAddress,
        Session.HTTP_SESSION_BINDING_ATTRIBUTE -> getIdpSession.getOrElse(null)))
    inTr -> new PlayResponseAdapter(inTr, request)
  }

  protected def callHandler(handler: String)(implicit inTr: PlayRequestAdapter, outTr: PlayResponseAdapter): Future[SimpleResult] = {
    val errorHandler = handlerManager.getErrorHandler
    val idpHandler = handlerManager.getProfileHandler(new ServletRequestMock(handler)).asInstanceOf[ProfileHandler[InTransport,OutTransport]]

    Try {
      if (idpHandler == null) {
        logger.error("No profile handler configured for request at path: {}", handler)
        throw new NoProfileHandlerException("No profile handler configured for request at path: " + handler)
      }
      idpHandler.processRequest(inTr, outTr)
    }.recoverWith {
      case pe: ProfileException =>
        inTr.setAttribute(AbstractErrorHandler.ERROR_KEY, pe)
        errorHandler.processRequest(inTr, outTr)
        Failure(pe)
      case _ @ t =>
        logger.error("Error occurred while processing request", t)
        errorHandler.processRequest(inTr, outTr)
        Failure(t)
    }

    outTr.result
}

protected class ServletRequestMock(private val handler: String) extends HttpServletRequest {

  override def getDispatcherType: DispatcherType = ???

  override def getAsyncContext: AsyncContext = ???

  override def isAsyncSupported: Boolean = ???

  override def isAsyncStarted: Boolean = ???

  override def startAsync(servletRequest: ServletRequest, servletResponse: ServletResponse): AsyncContext = ???

  override def startAsync(): AsyncContext = ???

  override def getServletContext: ServletContext = ???

  override def getLocalPort: Int = ???

  override def getLocalAddr: String = ???

  override def getLocalName: String = ???

  override def getRemotePort: Int = ???

  override def getRealPath(path: String): String = ???

  override def getRequestDispatcher(path: String): RequestDispatcher = ???

  override def isSecure: Boolean = ???

  override def getLocales: util.Enumeration[Locale] = ???

  override def getLocale: Locale = ???

  override def removeAttribute(name: String): Unit = ???

  override def setAttribute(name: String, o: scala.Any): Unit = ???

  override def getRemoteHost: String = ???

  override def getRemoteAddr: String = ???

  override def getReader: BufferedReader = ???

  override def getServerPort: Int = ???

  override def getServerName: String = ???

  override def getScheme: String = ???

  override def getProtocol: String = ???

  override def getParameterMap: util.Map[String, Array[String]] = ???

  override def getParameterValues(name: String): Array[String] = ???

  override def getParameterNames: util.Enumeration[String] = ???

  override def getParameter(name: String): String = ???

  override def getInputStream: ServletInputStream = ???

  override def getContentType: String = ???

  override def getContentLength: Int = ???

  override def setCharacterEncoding(env: String): Unit = ???

  override def getCharacterEncoding: String = ???

  override def getAttributeNames: util.Enumeration[String] = ???

  override def getAttribute(name: String): AnyRef = ???

  override def getPart(name: String): Part = ???

  override def getParts: util.Collection[Part] = ???

  override def logout(): Unit = ???

  override def login(username: String, password: String): Unit = ???

  override def authenticate(response: HttpServletResponse): Boolean = ???

  override def isRequestedSessionIdFromUrl: Boolean = ???

  override def isRequestedSessionIdFromURL: Boolean = ???

  override def isRequestedSessionIdFromCookie: Boolean = ???

  override def isRequestedSessionIdValid: Boolean = ???

  override def getSession: HttpSession = ???

  override def getSession(create: Boolean): HttpSession = ???

  override def getServletPath: String = ???

  override def getRequestURL: StringBuffer = ???

  override def getRequestURI: String = ???

  override def getRequestedSessionId: String = ???

  override def getUserPrincipal: Principal = ???

  override def isUserInRole(role: String): Boolean = ???

  override def getRemoteUser: String = ???

  override def getQueryString: String = ???

  override def getContextPath: String = ???

  override def getPathTranslated: String = ???

  override def getPathInfo: String = handler

  override def getMethod: String = ???

  override def getIntHeader(name: String): Int = ???

  override def getHeaderNames: util.Enumeration[String] = ???

  override def getHeaders(name: String): util.Enumeration[String] = ???

  override def getHeader(name: String): String = ???

  override def getDateHeader(name: String): Long = ???

  override def getCookies: Array[http.Cookie] = ???

  override def getAuthType: String = ???
}


}
