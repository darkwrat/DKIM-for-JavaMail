package com.github.darkwrat.dkim;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.util.Enumeration;

import javax.mail.MessagingException;
import javax.mail.Session;
import javax.mail.internet.MimeMessage;
import javax.mail.internet.MimeUtility;

import com.sun.mail.smtp.SMTPMessage;
import com.sun.mail.util.LineOutputStream;

/*
 * Extension of SMTPMessage for the inclusion of a DKIM signature.
 * 
 * @author Florian Sager, http://www.agitos.de, 22.11.2008
 */

public class SmtpDkimMessage extends SMTPMessage {

    private DkimSigner signer;
    private String encodedBody;

    public SmtpDkimMessage(Session session, DkimSigner signer) {
        super(session);
        this.signer = signer;
    }

    public SmtpDkimMessage(MimeMessage message, DkimSigner signer) throws MessagingException {
        super(message);
        this.signer = signer;
    }

    public SmtpDkimMessage(Session session, InputStream is, DkimSigner signer) throws MessagingException {
        super(session, is);
        this.signer = signer;
    }

    /**
     * Output the message as an RFC 822 format stream, without
     * specified headers.  If the <code>saved</code> flag is not set,
     * the <code>saveChanges</code> method is called.
     * If the <code>modified</code> flag is not
     * set and the <code>content</code> array is not null, the
     * <code>content</code> array is written directly, after
     * writing the appropriate message headers.
     *
     * @throws javax.mail.MessagingException
     * @throws IOException                   if an error occurs writing to the stream
     *                                       or if an error is generated by the
     *                                       javax.activation layer.
     * @see javax.activation.DataHandler#writeTo
     * <p>
     * This method enhances the JavaMail method MimeMessage.writeTo(OutputStream os String[] ignoreList);
     * See the according Sun Licence, this contribution is CDDL.
     */
    @Override
    public void writeTo(OutputStream os, String[] ignoreList) throws IOException, MessagingException {
        // Inside saveChanges() it is assured that content encodings are set in all parts of the body
        if (!saved) {
            saveChanges();
        }

        final ByteArrayOutputStream osBody = new ByteArrayOutputStream();
        // First, write out the body to the body buffer
        if (modified) {
            // Finally, the content. Encode if required.
            // XXX: May need to account for ESMTP ?
            final OutputStream osEncoding = MimeUtility.encode(osBody, this.getEncoding());
            this.getDataHandler().writeTo(osEncoding);
            osEncoding.flush(); // Needed to complete encoding
        } else {
            // Else, the content is untouched, so we can just output it
            // Finally, the content.
            if (content == null) {
                // call getContentStream to give subclass a chance to
                // provide the data on demand
                final InputStream is = getContentStream();
                // now copy the data to the output stream
                //noinspection MagicNumber
                byte[] buf = new byte[8 * 1024 /* bytes */];
                int len;
                while ((len = is.read(buf)) > 0)
                    osBody.write(buf, 0, len);
                is.close();
                buf = null;
            } else {
                osBody.write(content);
            }
            osBody.flush();
        }
        encodedBody = osBody.toString();

        // Second, sign the message
        final String signatureHeaderLine;
        try {
            signatureHeaderLine = signer.sign(this);
        } catch (Exception e) {
            throw new MessagingException(e.getLocalizedMessage(), e);
        }

        // Third, write out the header to the header buffer
        final LineOutputStream los = new LineOutputStream(os);

        // set generated signature to the top
        los.writeln(signatureHeaderLine);

        final Enumeration hdrLines = getNonMatchingHeaderLines(ignoreList);
        while (hdrLines.hasMoreElements()) {
            los.writeln((String) hdrLines.nextElement());
        }

        // The CRLF separator between header and content
        los.writeln();

        // Send signed mail to waiting DATA command
        os.write(osBody.toByteArray());
        os.flush();
    }

    public String getEncodedBody() {
        return encodedBody;
    }

    public void setEncodedBody(String encodedBody) {
        this.encodedBody = encodedBody;
    }

    // Don't allow to switch to 8-bit MIME, instead 7-bit ascii should be kept
    // 'cause in forwarding scenarios a change to Content-Transfer-Encoding
    // to 7-bit ascii breaks DKIM signatures
    @Override
    public void setAllow8bitMIME(boolean allow) {
        // super.setAllow8bitMIME(false);
    }
}