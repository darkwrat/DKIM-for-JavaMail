package com.github.darkwrat.dkim;

import java.io.File;
import java.io.FileInputStream;
import java.util.Properties;

import javax.activation.DataHandler;
import javax.activation.FileDataSource;
import javax.mail.MessagingException;
import javax.mail.Multipart;
import javax.mail.internet.MimeBodyPart;

/*
 * @author Florian Sager, http://www.agitos.de, 22.11.2008
 */

public class Utilities {

    public static String bodyText = "Hello,\r\n\r\nthis email was signed by the DKIM for JavaMail library.\r\n\r\nTo check the validity of DKIM signatures, send the generated emails directly to a DKIM test address like sa-test@sendmail.net with your personal email address in the From header.\r\n\r\nPromotional stuff: see www.dkim-reputation.org and consider using DKIM reputation for an improved spam filtering, especially for the reduction of false positives.\r\n\r\nRegards,\r\nFlorian Sager, www.agitos.de\r\n\r\n";

    public static Properties readProperties() {

        final Properties props = new Properties();
        try {
            props.load(new FileInputStream("test.properties"));
        } catch (Exception e) {
            msgAndExit("Check if the test configuration file 'test.properties' is in your classpath and if it's readable");
        }
        return props;
    }

    public static void printArray(String[] a) {

        for (int i = 0; i < a.length; i++) {
            System.out.println(i + ": " + a[i]);
        }

        System.out.println("---");
    }

    public static void msgAndExit(String msg) {
        System.out.println(msg);
        System.exit(0);
    }

    public static void addFileAttachment(Multipart mp, Object filename) throws MessagingException {

        if (filename == null) return;

        final File f = new File((String) filename);
        if (!f.exists() || !f.canRead()) {
            msgAndExit("Cannot read attachment file " + filename + ", sending stops");
        }

        final MimeBodyPart msgFile = new MimeBodyPart();
        final FileDataSource fds = new FileDataSource(f);
        msgFile.setDataHandler(new DataHandler(fds));
        msgFile.setFileName(f.getName());

        mp.addBodyPart(msgFile);
    }

}
