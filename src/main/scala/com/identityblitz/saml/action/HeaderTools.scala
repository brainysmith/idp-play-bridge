package com.identityblitz.saml.action

import play.api.mvc.{Cookies, Headers, Cookie, Request}
import play.mvc.Http.HeaderNames

/**
 */
trait HeaderTools {

  def addCookie(nv: (String, String))(implicit req: Request[_]) = {
    @inline def Headers(cookies: Seq[Cookie]) = new Headers {
      val data: Seq[(String, Seq[String])] = (req.headers.toMap + (HeaderNames.COOKIE -> Seq(Cookies.encode(cookies)))).toSeq
    }
    val cookie = Cookie(nv._1, nv._2)
    req.headers.get(HeaderNames.COOKIE).map(c =>Headers(
      Cookies.decode(c).filterNot(_.name == nv._1) :+ cookie
    )).getOrElse(Headers(
      Seq(cookie)
    ))
  }

}
