package com.acme.cxf.security;

import org.apache.wss4j.common.ext.WSPasswordCallback;
import javax.security.auth.callback.*;
import java.io.IOException;
import java.util.Map;

public class UTPasswordCallback implements CallbackHandler {
    private final Map<String,String> users;

    // Le constructeur prend une Map d'utilisateurs (Username -> Password)
    public UTPasswordCallback(Map<String,String> users) {
        this.users = users;
    }

    @Override
    public void handle(Callback[] callbacks) throws IOException, UnsupportedCallbackException {
        for (Callback cb : callbacks) {
            // WSPasswordCallback est spécifique à WSS4J pour traiter les jetons de mot de passe
            if (cb instanceof WSPasswordCallback pc) {
                String pass = users.get(pc.getIdentifier()); // pc.getIdentifier() est l'Username
                if (pass != null) {
                    pc.setPassword(pass); // Définit le mot de passe pour la vérification
                }
            }
        }
    }
}