package com.github.darkwrat.dkim;

/*
 * @author Florian Sager, http://www.agitos.de, 15.11.2008
 */

public class DkimSignerException extends Exception {

    public DkimSignerException(String message) {
        super(message);
    }

    public DkimSignerException(String message, Exception e) {
        super(message, e);
    }

}
