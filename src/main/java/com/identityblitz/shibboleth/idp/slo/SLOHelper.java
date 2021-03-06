package com.identityblitz.shibboleth.idp.slo;

import com.identityblitz.shibboleth.idp.saml.ws.transposrt.HTTPInTransportWithCookie;
import com.identityblitz.shibboleth.idp.saml.ws.transposrt.HTTPOutTransportWithCookie;
import edu.internet2.middleware.shibboleth.idp.slo.SingleLogoutContext;
import edu.internet2.middleware.shibboleth.idp.slo.SingleLogoutContextEntry;
import org.opensaml.util.storage.StorageService;
import org.opensaml.ws.transport.http.HTTPOutTransport;
import org.opensaml.xml.util.DatatypeHelper;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.UUID;

/**
 */
public class SLOHelper {

    private static final Logger log = LoggerFactory.getLogger(SLOHelper.class);

    /** Name of the key to the current single logout context: {@value} . */
    public static final String SLO_CTX_KEY_NAME = "_idp_slo_ctx_key";

    /** Default name for the {@link org.opensaml.util.storage.StorageService} partition which holds
     * {@link edu.internet2.middleware.shibboleth.idp.slo.SingleLogoutContext}s: {@value} . */
    public static final String DEFAULT_SLO_CTX_PARTITION = "sloContexts";


    public static SingleLogoutContext getSingleLogoutContext(HTTPOutTransport otr) {
        return (SingleLogoutContext) otr.getAttribute(SLO_CTX_KEY_NAME);
    }

    @SuppressWarnings("unchecked")
    public static SingleLogoutContext getSingleLogoutContext(StorageService storageService, HTTPInTransportWithCookie itr,
                                                             HTTPOutTransport otr) {
        if (storageService == null) {
            throw new IllegalArgumentException("Storage service may not be null");
        }
        if (itr == null) {
            throw new IllegalArgumentException("Inbound transport may not be null");
        }
        if (otr == null) {
            throw new IllegalArgumentException("Outbound transport may not be null");
        }

        SingleLogoutContext sloContext = getSingleLogoutContext(otr);
        if (sloContext == null) {
            log.debug("SingleLogoutContext not bound to HTTP request, retrieving it from storage service");
            final String sloContextKeyCookie = itr.getCookie(SLO_CTX_KEY_NAME);
            if (sloContextKeyCookie == null) {
                log.debug("SingleLogoutContext key cookie was not present in request");
                return null;
            }

            String sloContextKey = DatatypeHelper.safeTrimOrNullString(sloContextKeyCookie);
            if (sloContextKey == null) {
                log.warn("Corrupted SingleLogoutContext Key cookie, it did not contain a value");
            }
            log.debug("SingleLogoutContext key is '{}'", sloContextKey);

            String partition = DEFAULT_SLO_CTX_PARTITION;
            log.debug("partition: {}", partition);
            SingleLogoutContextEntry entry = (SingleLogoutContextEntry) storageService.get(partition, sloContextKey);
            if (entry != null) {
                if (entry.isExpired()) {
                    log.debug("SingleLogoutContext found but it was expired");
                } else {
                    sloContext = entry.getSingleLogoutContext();
                }
            } else {
                log.debug("No single logout context in storage service");
            }
        }

        return sloContext;

    }

    @SuppressWarnings("unchecked")
    public static void bindSingleLogoutContext(SingleLogoutContext sloContext, StorageService storageService,
                                               HTTPOutTransportWithCookie otr) {
        if (storageService == null) {
            throw new IllegalArgumentException("Storage service may not be null");
        }
        if (otr == null) {
            throw new IllegalArgumentException("Outbound HTTP transports may not be null");
        }
        if (sloContext == null) {
            return;
        }

        bindSingleLogoutContext(sloContext, otr);


        String partition = DEFAULT_SLO_CTX_PARTITION;
        log.debug("SingleLogoutContext partition: {}", partition);

        String contextKey = UUID.randomUUID().toString();
        while (storageService.contains(partition, contextKey)) {
            contextKey = UUID.randomUUID().toString();
        }
        log.debug("SingleLogoutContext key: {}", contextKey);

        SingleLogoutContextEntry entry = new SingleLogoutContextEntry(sloContext, 1800000);
        storageService.put(partition, contextKey, entry);

        if (log.isDebugEnabled()) {
            log.debug("SingleLogoutContext key: {}", contextKey);
        }
        otr.addCookie(SLO_CTX_KEY_NAME, contextKey);
    }

    public static void bindSingleLogoutContext(SingleLogoutContext sloContext, HTTPOutTransport otr) {
        if (otr == null) {
            throw new IllegalArgumentException("HTTP request may not be null");
        }
        otr.setAttribute(SLO_CTX_KEY_NAME, sloContext);
    }

    @SuppressWarnings("unchecked")
    public static SingleLogoutContext unbindSingleLogoutContext(StorageService storageService,
                                                                HTTPInTransportWithCookie itr, HTTPOutTransportWithCookie otr) {
        if (storageService == null || itr == null || otr == null) {
            return null;
        }

        String sloContextKey = removeSingleLogoutContextCookie(itr, otr);
        if (sloContextKey == null) {
            return null;
        }

        String partition = DEFAULT_SLO_CTX_PARTITION;
        SingleLogoutContextEntry entry = (SingleLogoutContextEntry) storageService.remove(partition, sloContextKey);
        if (entry != null && !entry.isExpired()) {
            return entry.getSingleLogoutContext();
        }
        return null;

    }

    /**
     * Removes cookie for SingleLogoutContext and returns the logout context key.
     */
    protected static String removeSingleLogoutContextCookie(HTTPInTransportWithCookie itr,
                                                            HTTPOutTransportWithCookie otr) {
        String sloContextKeyCookie = itr.getCookie(SLO_CTX_KEY_NAME);
        if (sloContextKeyCookie == null) {
            return null;
        }
        String sloContextKey = DatatypeHelper.safeTrimOrNullString(sloContextKeyCookie);
        if (sloContextKey == null) {
            log.warn("Corrupted SingleLogoutContext Key cookie, it did not contain a value");
        }

        otr.discardCookie(SLO_CTX_KEY_NAME);

        return sloContextKey;
    }
}
