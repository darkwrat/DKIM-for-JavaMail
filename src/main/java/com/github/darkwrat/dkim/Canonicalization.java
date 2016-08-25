package com.github.darkwrat.dkim;

import java.io.IOException;

/*
 * Provides Simple and Relaxed Canonicalization according to DKIM RFC 4871.
 * 
 * @author Florian Sager, http://www.agitos.de, 22.11.2008
 */

public class Canonicalization {

    public static Canonicalization SIMPLE = new Canonicalization() {

        public String getType() {

            return "simple";
        }

        public String canonicalizeHeader(String name, String value) {

            return name + ":" + value;
        }

        public String canonicalizeBody(String body) throws IOException {

            if (body == null || "".equals(body)) {
                return "\r\n";
            }

            // The body must end with \r\n
            if (!"\r\n".equals(body.substring(body.length() - 2, body.length()))) {
                return body + "\r\n";
            }

            // Remove trailing empty lines ...
            while ("\r\n\r\n".equals(body.substring(body.length() - 4, body.length()))) {
                body = body.substring(0, body.length() - 2);
            }

            return body;
        }
    };

    public static Canonicalization RELAXED = new Canonicalization() {

        public String getType() {

            return "relaxed";
        }

        public String canonicalizeHeader(String name, String value) {

            name = name.trim().toLowerCase();
            value = value.replaceAll("\\s+", " ").trim();
            return name + ":" + value;
        }

        public String canonicalizeBody(String body) throws IOException {

            if (body == null || "".equals(body)) {
                return "\r\n";
            }

            body = body.replaceAll("[ \\t\\x0B\\f]+", " ");
            body = body.replaceAll(" \r\n", "\r\n");

            // The body must end with \r\n
            if (!"\r\n".equals(body.substring(body.length() - 2, body.length()))) {
                return body + "\r\n";
            }

            // Remove trailing empty lines ...
            while ("\r\n\r\n".equals(body.substring(body.length() - 4, body.length()))) {
                body = body.substring(0, body.length() - 2);
            }

            return body;
        }
    };

    public Canonicalization() {
    }

    public String getType() {
        return "unknown";
    }

    public String canonicalizeHeader(String name, String value) {
        return null;
    }

    public String canonicalizeBody(String body) throws IOException {
        return null;
    }
}
