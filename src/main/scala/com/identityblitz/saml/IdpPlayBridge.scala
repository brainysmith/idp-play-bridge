package com.identityblitz.saml

import org.springframework.context.support.{ClassPathXmlApplicationContext, AbstractApplicationContext}
import org.slf4j.LoggerFactory
import com.identityblitz.saml.service.ServiceProvider.confService
import scala.Some

/**
 */
object IdpPlayBridge {

  private var _samlCtx: Option[AbstractApplicationContext] = None

  lazy val logger = LoggerFactory.getLogger("com.identityblitz.idp-play-bridge")

  lazy val contextPath = confService.getOptString("context-path").getOrElse("/saml")

  lazy val claimOfPrincipalName = confService.getOptString("claim-of-principal-name").getOrElse("uid")

  lazy val logoutPage = confService.logoutPage

  lazy val cookie = CookieConf(confService.getOptString("cookie.path").getOrElse("/"),
    confService.getOptString("cookie.domain"),
    confService.getOptBoolean("cookie.secure").getOrElse(true),
    confService.getOptBoolean("cookie.httpOnly").getOrElse(true))

  def init() = {
    _samlCtx = Some(new ClassPathXmlApplicationContext(Array("/internal.xml", "/service.xml")))
  }

  def samlCtx = _samlCtx.getOrElse(throw new IllegalStateException("Saml context not initialized. Be sure that you " +
    "call IdpPlayBridge.init() before."))

}

case class CookieConf(path: String, domain: Option[String], secure: Boolean, httpOnly: Boolean)
