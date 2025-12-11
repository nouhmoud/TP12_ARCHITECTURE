package com.acme.cxf;

import java.io.IOException;
import java.util.HashMap;
import java.util.Map;
import jakarta.security.auth.callback.Callback;
import jakarta.security.auth.callback.CallbackHandler;
import jakarta.security.auth.callback.UnsupportedCallbackException;
import org.apache.wss4j.common.ext.WSSecurityException;
import org.apache.wss4j.common.principal.CustomTokenPrincipal;
import org.apache.wss4j.dom.callback.PasswordValidationCallback;
import org.apache.wss4j.dom.callback.PasswordValidationCallback.PasswordValidationResult;

public class ServerPasswordCallback implements CallbackHandler {

    private Map<String, String> passwords = new HashMap<>();

    public ServerPasswordCallback() {
        // Utilisateurs autorisés
        passwords.put("alice", "passalice");
        passwords.put("bob", "passbob");
    }

    @Override
    public void handle(Callback[] callbacks) throws IOException, UnsupportedCallbackException {
        for (Callback callback : callbacks) {
            if (callback instanceof PasswordValidationCallback) {
                PasswordValidationCallback pvc = (PasswordValidationCallback) callback;

                // 1. Récupérer l'utilisateur soumis dans le message SOAP
                String username = pvc.getUsername();

                // 2. Vérifier si l'utilisateur existe dans notre liste
                if (passwords.containsKey(username)) {
                    String storedPassword = passwords.get(username);

                    // 3. Valider le mot de passe
                    if (pvc.getPassword().equals(storedPassword)) {
                        // Succès de l'authentification
                        pvc.setValidationResult(PasswordValidationResult.OK);
                        // Optional: Définir le principal de l'utilisateur
                        pvc.setPrincipal(new CustomTokenPrincipal(username));
                        return;
                    }
                }

                // Échec de la validation
                pvc.setValidationResult(PasswordValidationResult.FAILURE);
                throw new WSSecurityException(WSSecurityException.ErrorCode.FAILED_AUTHENTICATION);
            }
        }
    }
}