package com.github.darkwrat.dkim;

import java.util.Properties;

import javax.mail.Message;
import javax.mail.Session;
import javax.mail.Transport;
import javax.mail.internet.InternetAddress;

/* 
 * This example sends multiple DKIM signed emails with standard signature configuration.
 * This version of DKIM for JavaMail was tested with JavaMail 1.4.1, downward compatibility with 1.3 is expected.
 * 
 * @author Florian Sager, http://www.agitos.de, 22.11.2008
 */

public class MultipleMailExample {

    public static void main(String args[]) throws Exception {

        // read test configuration from test.properties in your classpath
        Properties testProps = TestUtil.readProperties();

        // get a JavaMail Session object
        Session session = Session.getDefaultInstance(testProps, null);

        Transport transport = session.getTransport("smtp");
        transport.connect(testProps.getProperty("mail.smtp.host"),
                testProps.getProperty("mail.smtp.auth.user"),
                testProps.getProperty("mail.smtp.auth.password"));


        ///////// beginning of DKIM FOR JAVAMAIL stuff

        // get DKIMSigner object
        DKIMSigner dkimSigner = new DKIMSigner(
                testProps.getProperty("mail.smtp.dkim.signingdomain"),
                testProps.getProperty("mail.smtp.dkim.selector"),
                testProps.getProperty("mail.smtp.dkim.privatekey"));

        for (int i = 0; i < 3; i++) {

			/* set an address or user-id of the user on behalf this message was signed;
			 * this identity is up to you, except the domain part must be the signing domain
			 * or a subdomain of the signing domain.
			 */
            dkimSigner.setIdentity("multipleexample" + i + "@" + testProps.getProperty("mail.smtp.dkim.signingdomain"));

            // construct the JavaMail message using the DKIM message type from DKIM for JavaMail
            Message msg = new SMTPDKIMMessage(session, dkimSigner);

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

            msg.setSubject("DKIM for JavaMail: MultipleExample Testmessage " + i);
            msg.setText(TestUtil.bodyText);

            // send the message by JavaMail
            transport.sendMessage(msg, msg.getAllRecipients());
        }

        transport.close();
    }
}
