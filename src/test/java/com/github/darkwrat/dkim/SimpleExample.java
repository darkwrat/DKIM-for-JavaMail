package com.github.darkwrat.dkim;

import java.util.Properties;

import javax.mail.Message;
import javax.mail.Session;
import javax.mail.Transport;
import javax.mail.internet.InternetAddress;

/* 
 * This example sends a DKIM signed email with standard signature configuration.
 * This version of DKIM for JavaMail was tested with JavaMail 1.4.1, downward compatibility with 1.3 is expected.
 * 
 * @author Florian Sager, http://www.agitos.de, 22.11.2008
 */

public class SimpleExample {

    public static void main(String[] args) throws Exception {

        // read test configuration from test.properties in your classpath
        final Properties testProps = Utilities.readProperties();

        // get a JavaMail Session object
        final Session session = Session.getDefaultInstance(testProps, null);


        ///////// beginning of DKIM FOR JAVAMAIL stuff

        // get DKIMSigner object
        final DkimSigner dkimSigner = new DkimSigner(
                testProps.getProperty("mail.smtp.dkim.signingdomain"),
                testProps.getProperty("mail.smtp.dkim.selector"),
                testProps.getProperty("mail.smtp.dkim.privatekey"));

        /* set an address or user-id of the user on behalf this message was signed;
         * this identity is up to you, except the domain part must be the signing domain
         * or a subdomain of the signing domain.
         */
        dkimSigner.setIdentity("simpleexample@" + testProps.getProperty("mail.smtp.dkim.signingdomain"));

        // construct the JavaMail message using the DKIM message type from DKIM for JavaMail
        final Message msg = new SmtpDkimMessage(session, dkimSigner);

        ///////// end of DKIM FOR JAVAMAIL stuff


        msg.setFrom(new InternetAddress(testProps.getProperty("mail.smtp.from")));
        if (testProps.getProperty("mail.smtp.to") != null) {
            msg.setRecipients(Message.RecipientType.TO,
                    InternetAddress.parse(testProps.getProperty("mail.smtp.to"), false));
        }
        if (testProps.getProperty("mail.smtp.cc") != null) {
            msg.setRecipients(Message.RecipientType.CC,
                    InternetAddress.parse(testProps.getProperty("mail.smtp.cc"), false));
        }

        msg.setSubject("DKIM for JavaMail: SimpleExample Testmessage");
        msg.setText(Utilities.bodyText);

        // send the message by JavaMail
        final Transport transport = session.getTransport("smtp");
        transport.connect(testProps.getProperty("mail.smtp.host"),
                testProps.getProperty("mail.smtp.auth.user"),
                testProps.getProperty("mail.smtp.auth.password"));
        transport.sendMessage(msg, msg.getAllRecipients());
        transport.close();
    }

}
