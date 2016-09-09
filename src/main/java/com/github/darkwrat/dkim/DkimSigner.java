package com.github.darkwrat.dkim;

import java.io.ByteArrayOutputStream;
import java.io.DataInputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.Signature;
import java.security.SignatureException;
import java.security.interfaces.RSAPrivateKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.ArrayList;
import java.util.Date;
import java.util.Enumeration;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Set;
import java.util.Map.Entry;

import javax.mail.MessagingException;

import com.sun.mail.util.CRLFOutputStream;


/*
 * Main class providing a signature according to DKIM RFC 4871.
 * 
 * @author Florian Sager, http://www.agitos.de, 15.10.2008
 */

public class DkimSigner {

    private static final String DKIM_SIGNATURE_HEADER = "DKIM-Signature";
    private static final int MAX_HEADER_LENGTH = 67;

    private static ArrayList<String> minimumHeadersToSign = new ArrayList<String>();

    static {
        minimumHeadersToSign.add("From");
        minimumHeadersToSign.add("Subject");
    }

    private String[] defaultHeadersToSign = new String[]{
            "Content-Description", "Content-ID", "Content-Type", "Content-Transfer-Encoding", "Cc",
            "Date", "From", "In-Reply-To", "List-Subscribe", "List-Post", "List-Owner", "List-Id",
            "List-Archive", "List-Help", "List-Unsubscribe", "MIME-Version", "Message-ID", "Resent-Sender",
            "Resent-Cc", "Resent-Date", "Resent-To", "Reply-To", "References", "Resent-Message-ID",
            "Resent-From", "Sender", "Subject", "To"};

    private SigningAlgorithm signingAlgorithm = SigningAlgorithm.SHA256withRSA; // use rsa-sha256 by default, see RFC 4871
    private Signature signatureService;
    private MessageDigest messageDigest;
    private String signingDomain;
    private String selector;
    private String identity = null;
    private boolean lengthParam = false;
    private boolean zParam = false;
    private Canonicalization headerCanonicalization = Canonicalization.RELAXED;
    private Canonicalization bodyCanonicalization = Canonicalization.SIMPLE;
    private PrivateKey privkey;

    public DkimSigner(String signingDomain, String selector, PrivateKey privkey) throws Exception {
        initDKIMSigner(signingDomain, selector, privkey);
    }

    public DkimSigner(String signingDomain, String selector, String privkeyFilename) throws Exception {

        final File privKeyFile = new File(privkeyFilename);

        // read private key DER file
        final DataInputStream dis = new DataInputStream(new FileInputStream(privKeyFile));
        final byte[] privKeyBytes = new byte[(int) privKeyFile.length()];
        dis.read(privKeyBytes);
        dis.close();

        final KeyFactory keyFactory = KeyFactory.getInstance("RSA");

        // decode private key
        final PKCS8EncodedKeySpec privSpec = new PKCS8EncodedKeySpec(privKeyBytes);
        final RSAPrivateKey privKey = (RSAPrivateKey) keyFactory.generatePrivate(privSpec);

        initDKIMSigner(signingDomain, selector, privKey);
    }

    private void initDKIMSigner(String signingDomain, String selector, PrivateKey privkey) throws DkimSignerException {

        if (!DkimUtil.isValidDomain(signingDomain)) {
            throw new DkimSignerException(signingDomain + " is an invalid signing domain");
        }

        this.signingDomain = signingDomain;
        this.selector = selector.trim();
        this.privkey = privkey;
        this.setSigningAlgorithm(this.signingAlgorithm);
    }

    public String getSigningDomain() {
        return signingDomain;
    }

    public String getSelector() {
        return selector;
    }

    public String getIdentity() {
        return identity;
    }

    public void setIdentity(String identity) throws DkimSignerException {

        if (identity != null) {
            identity = identity.trim();
            if (!identity.endsWith('@' + signingDomain) && !identity.endsWith('.' + signingDomain)) {
                throw new DkimSignerException("The domain part of " + identity + " has to be " + signingDomain + " or its subdomain");
            }
        }

        this.identity = identity;
    }

    public Canonicalization getBodyCanonicalization() {
        return bodyCanonicalization;
    }

    public void setBodyCanonicalization(Canonicalization bodyCanonicalization) throws DkimSignerException {
        this.bodyCanonicalization = bodyCanonicalization;
    }

    public Canonicalization getHeaderCanonicalization() {
        return headerCanonicalization;
    }

    public void setHeaderCanonicalization(Canonicalization headerCanonicalization) throws DkimSignerException {
        this.headerCanonicalization = headerCanonicalization;
    }

    public String[] getDefaultHeadersToSign() {
        return defaultHeadersToSign;
    }

    public void addHeaderToSign(String header) {

        if (header == null || header.isEmpty()) return;

        final int len = this.defaultHeadersToSign.length;
        final String[] headersToSign = new String[len + 1];
        for (int i = 0; i < len; i++) {
            if (header.equals(this.defaultHeadersToSign[i])) {
                return;
            }
            headersToSign[i] = this.defaultHeadersToSign[i];
        }

        headersToSign[len] = header;

        this.defaultHeadersToSign = headersToSign;
    }

    public void removeHeaderToSign(String header) {

        if (header == null || header.isEmpty()) return;

        final int len = this.defaultHeadersToSign.length;
        if (len == 0) return;

        final String[] headersToSign = new String[len - 1];

        int found = 0;
        for (int i = 0; i < len - 1; i++) {

            if (header.equals(this.defaultHeadersToSign[i + found])) {
                found = 1;
            }
            headersToSign[i] = this.defaultHeadersToSign[i + found];
        }

        this.defaultHeadersToSign = headersToSign;
    }

    public void setLengthParam(boolean lengthParam) {
        this.lengthParam = lengthParam;
    }

    public boolean getLengthParam() {
        return lengthParam;
    }

    public boolean isZParam() {
        return zParam;
    }

    public void setZParam(boolean param) {
        zParam = param;
    }

    public SigningAlgorithm getSigningAlgorithm() {
        return signingAlgorithm;
    }

    public void setSigningAlgorithm(SigningAlgorithm signingAlgorithm) throws DkimSignerException {

        try {
            this.messageDigest = MessageDigest.getInstance(signingAlgorithm.getJavaHashNotation());
        } catch (NoSuchAlgorithmException nsae) {
            throw new DkimSignerException("The hashing algorithm " + signingAlgorithm.getJavaHashNotation() + " is not known by the JVM", nsae);
        }

        try {
            this.signatureService = Signature.getInstance(signingAlgorithm.getJavaSecNotation());
        } catch (NoSuchAlgorithmException nsae) {
            throw new DkimSignerException("The signing algorithm " + signingAlgorithm.getJavaSecNotation() + " is not known by the JVM", nsae);
        }

        try {
            this.signatureService.initSign(privkey);
        } catch (InvalidKeyException ike) {
            throw new DkimSignerException("The provided private key is invalid", ike);
        }

        this.signingAlgorithm = signingAlgorithm;
    }

    private String serializeDKIMSignature(Map<String, String> dkimSignature) {

        final Set<Entry<String, String>> entries = dkimSignature.entrySet();
        final StringBuilder buf = new StringBuilder();
        int pos = 0;

        for (Entry<String, String> entry : entries) {
            // buf.append(entry.getKey()).append("=").append(entry.getValue()).append(";\t");

            final StringBuilder fbuf = new StringBuilder();
            fbuf.append(entry.getKey()).append('=').append(entry.getValue()).append(';');

            if (pos + fbuf.length() + 1 > MAX_HEADER_LENGTH) {

                pos = fbuf.length();

                // line folding : this doesn't work "sometimes" --> maybe someone likes to debug this
//                int i = 0;
//                while (i < pos) {
//                    if (fbuf.substring(i).length() > MAX_HEADER_LENGTH) {
//                        buf.append("\r\n\t").append(fbuf.substring(i, i + MAX_HEADER_LENGTH));
//                        i += MAX_HEADER_LENGTH;
//                    } else {
//                        buf.append("\r\n\t").append(fbuf.substring(i));
//                        pos -= i;
//                        break;
//                    }
//                }

                buf.append("\r\n\t").append(fbuf);

            } else {
                buf.append(' ').append(fbuf);
                pos += fbuf.length() + 1;
            }
        }

        buf.append("\r\n\tb=");

        return buf.toString().trim();
    }

    private String foldSignedSignature(String s, int offset) {

        int i = 0;
        final StringBuilder buf = new StringBuilder();

        while (true) {
            if (offset > 0 && s.substring(i).length() > MAX_HEADER_LENGTH - offset) {
                buf.append(s.substring(i, i + MAX_HEADER_LENGTH - offset));
                i += MAX_HEADER_LENGTH - offset;
                offset = 0;
            } else if (s.substring(i).length() > MAX_HEADER_LENGTH) {
                buf.append("\r\n\t").append(s.substring(i, i + MAX_HEADER_LENGTH));
                i += MAX_HEADER_LENGTH;
            } else {
                buf.append("\r\n\t").append(s.substring(i));
                break;
            }
        }

        return buf.toString();
    }

    public String sign(SmtpDkimMessage message) throws DkimSignerException, MessagingException {

        final Map<String, String> dkimSignature = new LinkedHashMap<String, String>();
        dkimSignature.put("v", "1");
        dkimSignature.put("a", this.signingAlgorithm.getRfc4871Notation());
        dkimSignature.put("q", "dns/txt");
        dkimSignature.put("c", headerCanonicalization.getType() + '/' + bodyCanonicalization.getType());
        dkimSignature.put("t", ((long) new Date().getTime() / 1000) + "");
        dkimSignature.put("s", this.selector);
        dkimSignature.put("d", this.signingDomain);

        // set identity inside signature
        if (identity != null) {
            dkimSignature.put("i", DkimUtil.QuotedPrintable(identity));
        }

        // process header
        final ArrayList assureHeaders = (ArrayList) minimumHeadersToSign.clone();

        // intersect defaultHeadersToSign with available headers
        final StringBuilder headerList = new StringBuilder();
        final StringBuilder headerContent = new StringBuilder();
        final StringBuilder zParamString = new StringBuilder();

        final Enumeration headerLines = message.getMatchingHeaderLines(defaultHeadersToSign);
        while (headerLines.hasMoreElements()) {
            final String header = (String) headerLines.nextElement();
            final String[] headerParts = DkimUtil.splitHeader(header);
            headerList.append(headerParts[0]).append(':');
            headerContent.append(this.headerCanonicalization.canonicalizeHeader(headerParts[0], headerParts[1])).append("\r\n");
            assureHeaders.remove(headerParts[0]);

            // add optional z= header list, DKIM-Quoted-Printable
            if (this.zParam) {
                zParamString.append(headerParts[0]).append(':').append(DkimUtil.QuotedPrintable(headerParts[1].trim()).replace("|", "=7C")).append('|');
            }
        }

        if (!assureHeaders.isEmpty()) {
            throw new DkimSignerException("Could not find the header fields " + DkimUtil.concatArray(assureHeaders, ", ") + " for signing");
        }

        dkimSignature.put("h", headerList.substring(0, headerList.length() - 1));

        if (this.zParam) {
            final String zParamTemp = zParamString.toString();
            dkimSignature.put("z", zParamTemp.substring(0, zParamTemp.length() - 1));
        }

        // process body
        String body = message.getEncodedBody();
        final ByteArrayOutputStream baos = new ByteArrayOutputStream();
        final CRLFOutputStream crlfos = new CRLFOutputStream(baos);
        try {
            crlfos.write(body.getBytes());
        } catch (IOException e) {
            throw new DkimSignerException("The body conversion to MIME canonical CRLF line terminator failed", e);
        }
        body = baos.toString();

        try {
            body = this.bodyCanonicalization.canonicalizeBody(body);
        } catch (IOException ioe) {
            throw new DkimSignerException("The body canonicalization failed", ioe);
        }

        if (this.lengthParam) {
            dkimSignature.put("l", body.length() + "");
        }

        // calculate and encode body hash
        dkimSignature.put("bh", DkimUtil.base64Encode(this.messageDigest.digest(body.getBytes())));

        // create signature
        final String serializedSignature = serializeDKIMSignature(dkimSignature);

        final byte[] signedSignature;
        try {
            signatureService.update(headerContent.append(this.headerCanonicalization.canonicalizeHeader(DKIM_SIGNATURE_HEADER, ' ' + serializedSignature)).toString().getBytes());
            signedSignature = signatureService.sign();
        } catch (SignatureException se) {
            throw new DkimSignerException("The signing operation by Java security failed", se);
        }

        return DKIM_SIGNATURE_HEADER + ": " + serializedSignature + foldSignedSignature(DkimUtil.base64Encode(signedSignature), 3);
    }
}
