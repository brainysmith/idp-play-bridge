package com.identityblitz.saml.action

import play.api.mvc.Controller
import com.identityblitz.login.glue.play.Forwardable

/**
  */
object Saml extends Controller with SsoBridge with SloBridge with HandlerBridge with SessionBridge with LoginContextBridge with HeaderTools {

  def profile(pathHandler: String) = Forwardable.async(parse.raw) { implicit request =>
    implicit val (inTr, outTr) = getTransports
    callHandler("/" + pathHandler)
  }

}
