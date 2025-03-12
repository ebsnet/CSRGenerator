package de.ebsnet.crmf;

import java.io.IOException;
import java.io.OutputStream;
import java.util.Objects;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.cmp.PKIMessage;
import org.bouncycastle.cms.CMSTypedData;

/** Trying to recreate the required ASN.1 structure for the renewal CSR. */
public class SignedCSRData implements CMSTypedData {
  // TODO: not sure what the correct OID is...
  public static final ASN1ObjectIdentifier CONTENT_TYPE =
      new ASN1ObjectIdentifier("0.4.0.127.0.7.4.1.1.2");
  private final PKIMessage data;

  public SignedCSRData(final PKIMessage data) {
    this.data = PKIMessage.getInstance(Objects.requireNonNull(data));
  }

  @Override
  public ASN1ObjectIdentifier getContentType() {
    //    return CONTENT_TYPE;
    return BSIPKIHeader.OID_BSI_CERT_REQ_MSGS;
  }

  @Override
  public void write(final OutputStream out) throws IOException {
    out.write(this.data.getEncoded());
  }

  @Override
  public Object getContent() {
    return PKIMessage.getInstance(this.data);
  }
}
