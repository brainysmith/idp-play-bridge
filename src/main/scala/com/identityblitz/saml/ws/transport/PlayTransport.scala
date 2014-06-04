package com.identityblitz.saml.ws.transport

import play.api.mvc.{RawBuffer, Request}

/**
 */
trait PlayTransport {

  def request: Request[RawBuffer]

  def getCharacterEncoding: String = request.charset.getOrElse(null)


}
