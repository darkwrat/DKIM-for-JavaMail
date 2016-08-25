package com.github.darkwrat.dkim;

/*
 * @author Florian Sager, http://www.agitos.de, 15.11.2008
 */

public class DKIMSignerException extends Exception {

    public DKIMSignerException(String message) {
        super(message);
    }

    public DKIMSignerException(String message, Exception e) {
        super(message, e);
    }

}
