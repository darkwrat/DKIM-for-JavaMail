package com.github.darkwrat.dkim;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.interfaces.RSAPrivateKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.ArrayList;
import java.util.Hashtable;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import javax.naming.NamingException;
import javax.naming.directory.Attribute;
import javax.naming.directory.Attributes;
import javax.naming.directory.DirContext;
import javax.naming.directory.InitialDirContext;

import org.jetbrains.annotations.Nullable;
import sun.misc.BASE64Encoder;

import com.sun.mail.util.QPEncoderStream;

/*
 * @author Florian Sager, http://www.agitos.de, 22.11.2008
 */

public class DkimUtil {

    protected static String[] splitHeader(String header) throws DkimSignerException {
        final int colonPos = header.indexOf(':');
        if (colonPos == -1) {
            throw new DkimSignerException("The header string " + header + " is no valid RFC 822 header-line");
        }
        return new String[]{header.substring(0, colonPos), header.substring(colonPos + 1)};
    }

    protected static String concatArray(ArrayList l, String separator) {
        final StringBuilder buf = new StringBuilder();
        for (Object aL : l) {
            buf.append(aL).append(separator);
        }

        return buf.substring(0, buf.length() - separator.length());
    }

    protected static boolean isValidDomain(String domainname) {
        final Pattern pattern = Pattern.compile("(.+)\\.(.+)");
        final Matcher matcher = pattern.matcher(domainname);
        return matcher.matches();
    }

    // FSTODO: converts to "platforms default encoding" might be wrong ?
    protected static @Nullable String QuotedPrintable(String s) {

        try {
            final ByteArrayOutputStream boas = new ByteArrayOutputStream();
            final QPEncoderStream encodeStream = new QPEncoderStream(boas);
            encodeStream.write(s.getBytes());

            String encoded = boas.toString();
            encoded = encoded.replaceAll(";", "=3B");
            encoded = encoded.replaceAll(" ", "=20");

            return encoded;

        } catch (IOException ignored) {
        }

        return null;
    }

    protected static String base64Encode(byte[] b) {
        final BASE64Encoder base64Enc = new BASE64Encoder();
        String encoded = base64Enc.encode(b);
        // remove unnecessary linefeeds after 76 characters
        encoded = encoded.replace("\n", ""); // Linux+Win
        return encoded.replace("\r", ""); // Win --> FSTODO: select Encoder without line termination
    }

    public boolean checkDNSForPublickey(String signingDomain, String selector) throws DkimSignerException {

        final Hashtable<String, String> env = new Hashtable<>();
        env.put("java.naming.factory.initial", "com.sun.jndi.dns.DnsContextFactory");
        final String recordname = selector + "._domainkey." + signingDomain;
        String value = null;

        try {
            final DirContext dnsContext = new InitialDirContext(env);

            final Attributes attribs = dnsContext.getAttributes(recordname, new String[]{"TXT"});
            final Attribute txtrecord = attribs.get("txt");

            if (txtrecord == null) {
                throw new DkimSignerException("There is no TXT record available for " + recordname);
            }

            // "v=DKIM1; g=*; k=rsa; p=MIGfMA0G ..."
            value = (String) txtrecord.get();

        } catch (NamingException ne) {
            throw new DkimSignerException("Selector lookup failed", ne);
        }

        if (value == null) {
            throw new DkimSignerException("Value of RR " + recordname + " couldn't be retrieved");
        }

        // try to read public key from RR
        final String[] tags = value.split(";");
        for (String tag : tags) {
            tag = tag.trim();
            if (tag.startsWith("p=")) {

                try {
                    final KeyFactory keyFactory = KeyFactory.getInstance("RSA");

                    // decode public key, FSTODO: convert to DER format
                    final PKCS8EncodedKeySpec pubSpec = new PKCS8EncodedKeySpec(tag.substring(2).getBytes());
                    final RSAPrivateKey pubKey = (RSAPrivateKey) keyFactory.generatePublic(pubSpec);
                } catch (NoSuchAlgorithmException nsae) {
                    throw new DkimSignerException("RSA algorithm not found by JVM", nsae);
                } catch (InvalidKeySpecException ikse) {
                    throw new DkimSignerException("The public key " + tag + " in RR " + recordname + " couldn't be decoded.", ikse);
                }

                // FSTODO: create test signature with privKey and test validation with pubKey to check on a valid key pair

                return true;
            }
        }

        throw new DkimSignerException("No public key available in " + recordname);
    }

}
