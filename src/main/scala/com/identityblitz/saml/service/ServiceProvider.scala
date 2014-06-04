package com.identityblitz.saml.service

import java.util.ServiceLoader
import com.identityblitz.saml.service.spi.IdpPlayBridgeConfService

/**
 */
object ServiceProvider {

  lazy val confService = {
    val csItr = ServiceLoader.load(classOf[IdpPlayBridgeConfService]).iterator()
    if(!csItr.hasNext)
      throw new RuntimeException("log configuration service is undefined.")
    csItr.next()
  }

}
