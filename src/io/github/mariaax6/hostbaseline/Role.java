package io.github.mariaax6.hostbaseline;

import java.util.Locale;

/** Host role selecting the baseline variant (only IPv4 forwarding differs today). */
public enum Role {
    WORKSTATION, ROUTER;

    public static Role parse(String text) {
        if (text != null) {
            switch (text.toLowerCase(Locale.ROOT)) {
                case "workstation": return WORKSTATION;
                case "router": return ROUTER;
                default: break;
            }
        }
        throw new IllegalArgumentException("Role must be workstation or router");
    }

    public String id() { return name().toLowerCase(Locale.ROOT); }
}
