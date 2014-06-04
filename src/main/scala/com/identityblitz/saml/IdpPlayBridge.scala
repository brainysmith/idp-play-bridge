package com.identityblitz.saml

import org.springframework.context.support.{ClassPathXmlApplicationContext, AbstractApplicationContext}
import org.slf4j.LoggerFactory
import com.identityblitz.saml.service.ServiceProvider.confService
/**
 */
object IdpPlayBridge {

  private var _samlCtx: Option[AbstractApplicationContext] = None

  lazy val logger = LoggerFactory.getLogger("com.identityblitz.idp-play-bridge")

  lazy val contextPath = confService.getOptString("context-path").getOrElse("/saml")

  lazy val logoutPage = confService.logoutPage

  def init() = {
    _samlCtx = Some(new ClassPathXmlApplicationContext(Array("/internal.xml", "/service.xml")))
  }

  def samlCtx = _samlCtx.getOrElse(throw new IllegalStateException("Saml context not initialized. Be sure that you " +
    "call IdpPlayBridge.init() before."))

}
