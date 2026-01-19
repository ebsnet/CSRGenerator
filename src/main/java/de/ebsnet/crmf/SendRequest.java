package de.ebsnet.crmf;

import com.sun.xml.ws.api.message.Headers;
import com.sun.xml.ws.developer.WSBindingProvider;
import com.sun.xml.ws.fault.ServerSOAPFaultException;
import edu.umd.cs.findbugs.annotations.SuppressFBWarnings;
import jakarta.xml.ws.BindingProvider;
import java.io.IOException;
import java.net.Socket;
import java.net.URI;
import java.net.URL;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;
import java.security.KeyManagementException;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.UnrecoverableKeyException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.Base64;
import java.util.Optional;
import java.util.concurrent.Callable;
import java.util.logging.Logger;
import javax.net.ssl.HttpsURLConnection;
import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLEngine;
import javax.net.ssl.TrustManager;
import javax.net.ssl.X509ExtendedTrustManager;
import javax.xml.namespace.QName;
import org.bouncycastle.jsse.provider.BouncyCastleJsseProvider;
import org.bouncycastle.util.io.pem.PemObject;
import org.bouncycastle.util.io.pem.PemObjectGenerator;
import org.bouncycastle.util.io.pem.PemWriter;
import picocli.CommandLine.Command;
import picocli.CommandLine.Option;
import uri.bsi_bund_de.smart_meter_pki_protocol._1.CallbackIndicatorType;
import uri.bsi_bund_de.smart_meter_pki_protocol._1.RequestCertificateReq;
import uri.bsi_bund_de.smart_meter_pki_protocol._1_3.SmartMeterService;

/**
 * This subcommand can be used to send a renewal CSR to the SubCA's renewal webservice.
 *
 * <p>This is not fully tested, since we currently cannot generate renewal CSRs
 */
@Command(name = "send", mixinStandardHelpOptions = true, description = "Send a Request for Renewal")
@SuppressWarnings("PMD.ExcessiveImports")
public final class SendRequest implements Callable<Void> {
  // we initialize here to, in case we are testing from a main method inside this
  // class
  static {
    CSRGenerator.init();
  }

  private static final Logger LOG = Logger.getLogger(SendRequest.class.getSimpleName());

  @Option(
      names = {"--tls-key"},
      required = true,
      description = "Path to the currently valid TLS key")
  private Path tlsKeyPath;

  @Option(
      names = {"--tls-key-pass"},
      description = "Password for the TLS key")
  private Optional<char[]> tlsKeyPass;

  @Option(
      names = {"--tls-cert"},
      required = true,
      description = "Path to the currently valid TLS cert")
  private Path tlsCertPath;

  @Option(
      names = {"--csr"},
      required = true,
      description = "Path to the new CSR")
  private Path csrPath;

  @Option(
      names = {"--out"},
      required = true,
      description = "Output directory to write the new certificates into")
  private Path out;

  @Option(
      names = {"--uri"},
      required = true,
      description = "Webservice URI")
  private URI uri;

  //  @SuppressFBWarnings("DMI_HARDCODED_ABSOLUTE_FILENAME")
  //  public static void main(final String[] args)
  //      throws UnrecoverableKeyException,
  //          CertificateException,
  //          IOException,
  //          NoSuchAlgorithmException,
  //          KeyStoreException,
  //          NoSuchProviderException,
  //          KeyManagementException {
  //    final var sendRequest = new SendRequest();
  //    sendRequest.tlsCertPath =
  //        Path.of("/home/me/Dokumente/work/keys/old/personalTLSCertificate.pem");
  //    sendRequest.tlsKeyPath = Path.of("/home/me/Dokumente/work/keys/old/tls.pem");
  //    sendRequest.csrPath = Path.of("./keys/new/csr.pem");
  //    sendRequest.uri =
  //        //      URI.create("http://localhost:8080");
  //        URI.create("https://test.sub-ca.da-rz.net:8443/metering-ca/services/SmartMeterService");
  //    sendRequest.out = Path.of("/home/me/Dokumente/work");
  //    sendRequest.call();
  //  }

  private SSLContext sslContext()
      throws NoSuchAlgorithmException,
          NoSuchProviderException,
          IOException,
          CertificateException,
          KeyStoreException,
          UnrecoverableKeyException,
          KeyManagementException {
    final var pwd = Utils.randomPwd();
    final var sslContext =
        SSLContext.getInstance("TLSv1.2", BouncyCastleJsseProvider.PROVIDER_NAME);
    final var keyStore =
        PEM2PKCS12.pemToPKCS12(this.tlsKeyPath, this.tlsKeyPass, this.tlsCertPath, "tls", pwd);

    final var kmf = KeyManagerFactory.getInstance("PKIX", BouncyCastleJsseProvider.PROVIDER_NAME);

    kmf.init(keyStore, pwd);

    sslContext.init(kmf.getKeyManagers(), new TrustManager[] {new TrustAll()}, null);

    return sslContext;
  }

  @Override
  public Void call()
      throws IOException,
          UnrecoverableKeyException,
          CertificateException,
          NoSuchAlgorithmException,
          KeyStoreException,
          NoSuchProviderException,
          KeyManagementException {
    try {
      final var sslContext = sslContext();

      final var csr = Files.readAllBytes(this.csrPath);
      Files.createDirectories(out);

      HttpsURLConnection.setDefaultSSLSocketFactory(sslContext.getSocketFactory());
      final var url = new URL(this.uri.toString());
      final var service = new SmartMeterService();
      final var port = service.getSmartMeterServicePort();

      final var context = ((BindingProvider) port).getRequestContext();
      context.put(
          "com.sun.xml.internal.ws.transport.https.client.SSLSocketFactory",
          sslContext.getSocketFactory());
      context.put(BindingProvider.ENDPOINT_ADDRESS_PROPERTY, url.toString());

      ((WSBindingProvider) port).setOutboundHeaders(Headers.create(new QName("certType"), "EMT"));

      final var req = new RequestCertificateReq();
      req.setCallbackIndicator(CallbackIndicatorType.CALLBACK_NOT_POSSIBLE);
      req.setCertReq(csr);
      final var serviceStatus = port.requestCertificate(req);
      LOG.info(() -> "Return Code: " + serviceStatus.getReturnCode());
      LOG.info(() -> "Return Code Message: " + serviceStatus.getReturnCodeMessage());
      final var b64 = Base64.getEncoder();

      for (final var crt : serviceStatus.getCertificateSeq().getCertificate()) {
        try {
          final var type = KeyType.fromCertificate(crt);
          final var filename =
              type.map(KeyType::filename)
                  .orElseGet(
                      () -> {
                        final var fallbackName = String.valueOf(Utils.randomPwd());
                        LOG.severe(() -> "cannot determine key type... storing in " + fallbackName);
                        return fallbackName;
                      });
          writePem(out.resolve(filename), crt, "CERTIFICATE");
          final var encoded = b64.encodeToString(crt);
          LOG.info(() -> "CRT " + type + ": " + encoded);
        } catch (IOException ex) {
          LOG.severe(() -> "error writing certificate to disk: " + ex);
        }
      }

      return null;
    } catch (ServerSOAPFaultException ssfe) {
      LOG.severe(() -> ssfe.getFault().toString());
      LOG.severe(() -> "Code: " + ssfe.getFault().getFaultCode());
      LOG.severe(() -> "Text: " + ssfe.getFault().getFaultString());
      throw ssfe;
    }
  }

  /* default */ static void writePem(final Path path, final byte[] content, final String type)
      throws IOException {
    writePem(path, new PemObject(type, content));
  }

  private static void writePem(final Path path, final PemObjectGenerator content)
      throws IOException {
    try (var writer = new PemWriter(Files.newBufferedWriter(path, StandardOpenOption.CREATE_NEW))) {
      writer.writeObject(content);
    }
  }

  /**
   * Trust manager that accepts any server certificate. We are only sending CSRs to the webservice,
   * which do not contain sensitive data. Everything inside the CSR will be in the public
   * certificate anyway. A proper implementation might extract the intermediate and root certificate
   * from the CSR to use as trust anchor.
   */
  @SuppressFBWarnings("WEAK_TRUST_MANAGER")
  private static final class TrustAll extends X509ExtendedTrustManager {

    @Override
    public void checkClientTrusted(
        final X509Certificate[] chain, final String authType, final Socket socket)
        throws CertificateException {}

    @Override
    public void checkServerTrusted(
        final X509Certificate[] chain, final String authType, final Socket socket)
        throws CertificateException {}

    @Override
    public void checkClientTrusted(
        final X509Certificate[] chain, final String authType, final SSLEngine engine)
        throws CertificateException {}

    @Override
    public void checkServerTrusted(
        final X509Certificate[] chain, final String authType, final SSLEngine engine)
        throws CertificateException {}

    @Override
    public void checkClientTrusted(final X509Certificate[] chain, final String authType)
        throws CertificateException {}

    @Override
    public void checkServerTrusted(final X509Certificate[] chain, final String authType)
        throws CertificateException {}

    @Override
    public X509Certificate[] getAcceptedIssuers() {
      return new X509Certificate[0];
    }
  }
}
