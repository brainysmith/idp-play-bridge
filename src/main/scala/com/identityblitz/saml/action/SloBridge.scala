package com.identityblitz.saml.action

import play.api.mvc.{Action, RequestHeader, Controller, SimpleResult}
import play.mvc.Http.HeaderNames
import com.identityblitz.saml.ws.transport.{PlayResponseAdapter, PlayRequestAdapter}
import com.identityblitz.shibboleth.idp.slo.SLOHelper
import scala.collection.convert.WrapAsScala
import java.util.Locale
import com.identityblitz.login.glue.play.{LogoutRequest, LogoutAction, Forwardable}
import scala.concurrent.Future
import com.identityblitz.saml.IdpPlayBridge._
import scala.Some
import scala.Tuple4
import org.opensaml.util.storage.StorageService
import edu.internet2.middleware.shibboleth.idp.authn.LoginContextEntry
import play.api.libs.json.{JsArray, JsObject, JsString}
import scala.language.reflectiveCalls

/**
 */
trait SloBridge {
  this: Controller with HandlerBridge with HeaderTools =>

  private lazy val storageService = samlCtx.getBean("shibboleth.StorageService").asInstanceOf[StorageService[String, LoginContextEntry]]

  private val headers = Seq(HeaderNames.CACHE_CONTROL -> "no-cache, must-revalidate", HeaderNames.PRAGMA -> "no -cache")

  def startLogout(implicit itr: PlayRequestAdapter, otr: PlayResponseAdapter) = LogoutAction.run(parse.anyContent) { req =>
    Option(SLOHelper.getSingleLogoutContext(otr)).fold[RequestHeader]{
      logger.error("Single Logout servlet can not be called directly")
      throw new IllegalStateException("Single Logout servlet can not be called directly")
    }{ sloContex => {
      SLOHelper.bindSingleLogoutContext(sloContex, storageService, otr)
      val sloContextKey = otr.cookies.find(_.name == SLOHelper.SLO_CTX_KEY_NAME).map(_.value).getOrElse{
        logger.error("Can't find logout context key in the outbound transport")
        throw new IllegalStateException("Can't find logout context key in the outbound transport")
      }
      val lr = LogoutRequest.builder.withCallbackUri("fwd:" + contextPath + "/logout/page").build()
      req.copy(tags = req.tags ++ lr.toMap, headers = addCookie(SLOHelper.SLO_CTX_KEY_NAME, sloContextKey)(req))
    }}
  }

  def toLogoutPage = Action(parse.raw) {
    implicit req => {
      implicit val (itr, otr) = getTransports
      Option(SLOHelper.getSingleLogoutContext(storageService, itr, otr)).fold[SimpleResult]{
        logger.error("Single Logout servlet can not be called directly")
        otr.discardCookie(SLOHelper.SLO_CTX_KEY_NAME)
        NotFound.discardingCookies()
      }{ sloContex => {
        val services = WrapAsScala.collectionAsScalaIterable(sloContex.getServiceInformation.values())
          .map(s => Tuple4(s.getDisplayName(new Locale("en"), new Locale("en")),
          s.getEntityID,
          s.getLogoutStatus.toString,
          s.isLoggedIn)).toSeq
        Ok(logoutPage(services, req)).withHeaders(headers: _*)
      }}
    }}

  def logoutAction =  Forwardable.async(parse.raw) {
    implicit req => {
      implicit val (itr, otr) = getTransports
      Option(SLOHelper.getSingleLogoutContext(storageService, itr, otr)).fold[Future[SimpleResult]]{
        logger.error("Single Logout servlet can not be called directly")
        otr.discardCookie(SLOHelper.SLO_CTX_KEY_NAME)
        Future.successful(NotFound)
      }{ sloContext =>
        SLOHelper.bindSingleLogoutContext(sloContext, otr)
        (req.getQueryString("status"), req.getQueryString("action"), req.getQueryString("finish")) match {
          case (Some(_), None, None) =>
            sloContext.checkTimeout()
            val services = WrapAsScala.collectionAsScalaIterable(sloContext.getServiceInformation.values())
            val res = collection.mutable.ArrayBuffer[JsObject]()
            for (s <- services) {
              res += JsObject(Seq("entityID" -> JsString(s.getEntityID),
                "logoutStatus" -> JsString(s.getLogoutStatus.toString)))
            }
            Future.successful(Ok(JsArray(res)).withHeaders(headers: _*))
          case (None, Some(_), None) =>
            callHandler(sloContext.getProfileHandlerURL)
          case (None, None, Some(_)) =>
            SLOHelper.unbindSingleLogoutContext(storageService, itr, otr)
            SLOHelper.bindSingleLogoutContext(sloContext, otr)
            callHandler(sloContext.getProfileHandlerURL)
          case _ =>
            val err = s"Unknown logout action [query string = ${req.rawQueryString}]"
            logger.error(err)
            throw new IllegalArgumentException(err)
        }}
    }
  }
}
