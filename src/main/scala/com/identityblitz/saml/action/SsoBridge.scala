package com.identityblitz.saml.action

import com.identityblitz.saml.ws.transport.{PlayResponseAdapter, PlayRequestAdapter}
import com.identityblitz.login.glue.play.{Forwardable, LoginRequest, LoginAction}
import play.api.mvc.{Controller, AnyContent, Request}
import com.identityblitz.saml.IdpPlayBridge._
import scala.Some
import com.identityblitz.login.RelyingParty
import com.identityblitz.shibboleth.idp.util.HttpHelper
import com.identityblitz.json.JVal
import javax.security.auth.Subject
import com.identityblitz.saml.SamlPrincipal
import org.joda.time.DateTime
import edu.internet2.middleware.shibboleth.idp.session.impl.{ServiceInformationImpl, AuthenticationMethodInformationImpl}
import edu.internet2.middleware.shibboleth.idp.authn.AuthenticationException
import scala.language.reflectiveCalls

/**
 */
trait SsoBridge {

  this: Controller with HandlerBridge with SessionBridge with LoginContextBridge with HeaderTools =>

  /**todo: rewrite - it's version only for prototype **/
  def startLogin(implicit inTr: PlayRequestAdapter, outTr: PlayResponseAdapter) = LoginAction.run(parse.anyContent) {
    implicit req: Request[AnyContent] => {
      val idpLgnCtx = Option(getIdpLoginContext).orElse({
        val err = "No login context available, unable to proceed with authentication"
        logger.error(err)
        throw new IllegalStateException(err)
      }).get

      idpLgnCtx.setAuthenticationAttempted()
      //idpLc.setAuthenticationEngineURL()

      val lr = LoginRequest.lrBuilder
        .withCallbackUri("fwd:" + contextPath + "/complete")
        .withRelyingParty(new RelyingParty {
        override def description: Option[String] = ???
        override def host: String = ???
        override def name: String = ???
      }).build()

      /** put the idp login context key into request cookies (mainly for sso case)**/
      req.copy(tags = req.tags ++ lr.toMap, headers = addCookie(HttpHelper.LOGIN_CTX_KEY_NAME, idpLgnCtx.getContextKey))
    }
  }

  /**todo: rewrite - it's version only for prototype **/
  def completeLogin = Forwardable.async(parse.raw) { implicit request =>
    if (logger.isTraceEnabled)
      logger.trace("Completing login process by SAML")

    val blitzLs = JVal.parseStr(request.tags("ls"))
    val claims = blitzLs \ "claims"
    val sbj = new Subject()
    val prn = SamlPrincipal(claims)

    implicit val (inTr, outTr) = getTransports
    implicit val idpLgnCtx = getIdpLoginContext
    request.tags.get("error").fold{
      /** the login complete successfully **/
      idpLgnCtx.setPrincipalAuthenticated(true)
      getIdpSession.orElse{
        if (logger.isDebugEnabled)
          logger.debug("Creating shibboleth session for principal {}", prn)
        val idpSession = createIdpSession
        idpLgnCtx.setSessionID(idpSession.getSessionID)
        Some(idpSession)
      }.map(idpSession => {
        sbj.getPrincipals.add(prn)
        idpSession.setSubject(sbj)
        /** create authentication method information **/
        val aInstant = new DateTime()
        /*todo: add an authentication duration to the blitz login session*/
        val aDuration = 30*60*1000
        val aMethod = (blitzLs \ "completedMethods").as[Array[String]].mkString(",")
        val aMethodInfo = new AuthenticationMethodInformationImpl(sbj, prn, aMethod, aInstant, aDuration)
        idpLgnCtx.setAuthenticationMethodInformation(aMethodInfo)
        idpSession.addAuthenticationMethods(aMethod, aMethodInfo)

        /** create service information **/
        val serviceInfo = new ServiceInformationImpl(idpLgnCtx.getRelyingPartyId, new DateTime, aMethodInfo)
        idpSession.addServicesInformation(serviceInfo.getEntityID, serviceInfo)
      })
      if (logger.isDebugEnabled)
        logger.debug("User [principal = {}] authenticated with method {}", Array(prn, idpLgnCtx.getAuthenticationMethod))
    }{error => {
      /** some error has occurred **/
      idpLgnCtx.setPrincipalAuthenticated(false)
      idpLgnCtx.setAuthenticationFailure(new AuthenticationException(error))
    }}

    callHandler(idpLgnCtx.getProfileHandlerURL)
  }

}
