package com.identityblitz.saml.action

import com.identityblitz.saml.ws.transport.{PlayResponseAdapter, PlayRequestAdapter}
import com.identityblitz.login.glue.play.{Forwardable, LoginRequest, LoginAction}
import play.api.mvc.{Controller, AnyContent, Request}
import com.identityblitz.saml.IdpPlayBridge._
import scala.Some
import com.identityblitz.login.{BuiltInRelyingParty, LoginFramework, FlowAttrName}
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
        .withRelyingParty(BuiltInRelyingParty(idpLgnCtx.getRelyingPartyId, "SAML"))
        .build()

      /** put the idp login context key into request cookies (mainly for sso case)**/
      req.copy(tags = req.tags ++ lr.toMap, headers = addCookie(HttpHelper.LOGIN_CTX_KEY_NAME, idpLgnCtx.getContextKey))
    }
  }

  def completeLogin = Forwardable.async(parse.raw) { implicit request =>
    if (logger.isTraceEnabled)
      logger.trace("Completing login process by SAML")
    implicit val (inTr, outTr) = getTransports
    implicit val idpLgnCtx = getIdpLoginContext

    def fail(error: String) = {
      /** some error has occurred **/
      logger.warn("Authentication failure: {}", error)
      idpLgnCtx.setPrincipalAuthenticated(false)
      idpLgnCtx.setAuthenticationFailure(new AuthenticationException(error))
    }

    def success() = {
      /** the login complete successfully **/
      val blitzLs = JVal.parseStr(request.tags("ls"))
      if (logger.isDebugEnabled)
        logger.debug("Authentication is successful: {}", blitzLs.toJson)
      val claims = blitzLs \ "claims"
      val sbj = new Subject()
      val prn = SamlPrincipal(claims)
      idpLgnCtx.setPrincipalAuthenticated(true)
      getIdpSession.orElse{
        logger.debug("Creating shibboleth session for principal {}", prn)
        val idpSession = createIdpSession
        idpLgnCtx.setSessionID(idpSession.getSessionID)
        Some(idpSession)
      }.map(idpSession => {
        sbj.getPrincipals.add(prn)
        idpSession.setSubject(sbj)
        /** create authentication method information **/
        val aInstant = new DateTime()
        val aDuration = LoginFramework.sessionConf.ttl
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
    }

    request.tags.get(FlowAttrName.ERROR).fold(success())(fail)
    callHandler(idpLgnCtx.getProfileHandlerURL)
  }
}
