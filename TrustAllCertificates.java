package br.gov.go.detran.rs.client;

import br.gov.go.detran.core.exception.ValidationException;
import br.gov.go.detran.util.LogDetranUtil;

import javax.net.ssl.*;
import java.security.KeyManagementException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.X509Certificate;

public final class TrustAllCertificates implements X509TrustManager, HostnameVerifier {
    public X509Certificate[] getAcceptedIssuers() {
        return null;
    }

    public void checkClientTrusted(X509Certificate[] certs, String authType) {
        LogDetranUtil.debug("checkClientTrusted");
    }

    public void checkServerTrusted(X509Certificate[] certs, String authType) {
        LogDetranUtil.debug("checkServerTrusted");
    }

    public boolean verify(String hostname, SSLSession session) {
        return true;
    }

    /**
     * Installs a new {@link TrustAllCertificates} as trust manager and hostname verifier.
     */
    public static void install() throws ValidationException {
        try {
            TrustAllCertificates trustAll = new TrustAllCertificates();

            // Install the all-trusting trust manager
            SSLContext sc = SSLContext.getInstance("SSL");
            sc.init(null,
                    new TrustManager[]{trustAll},
                    new java.security.SecureRandom());
            HttpsURLConnection.setDefaultSSLSocketFactory(sc.getSocketFactory());

            // Install the all-trusting host verifier
            HttpsURLConnection.setDefaultHostnameVerifier(trustAll);

        } catch (NoSuchAlgorithmException e) {
            throw new ValidationException("Failed setting up all thrusting certificate manager.", e);
        } catch (KeyManagementException e) {
            throw new ValidationException("Failed setting up all thrusting certificate manager.", e);
        }
    }
}