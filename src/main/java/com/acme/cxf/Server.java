package com.acme.cxf;

import com.acme.cxf.impl.HelloServiceImpl;
import org.apache.cxf.jaxws.JaxWsServerFactoryBean;
import org.apache.cxf.ws.security.wss4j.WSS4JInInterceptor;
import org.apache.wss4j.dom.WSConstants;
import java.util.HashMap;
import java.util.Map;

public class Server {
    public static void main(String[] args) {
        // --- Endpoint 1: Non sécurisé (comme avant) ---
        String addressUnsecured = "http://localhost:8080/services/hello";
        JaxWsServerFactoryBean factoryUnsecured = new JaxWsServerFactoryBean();
        factoryUnsecured.setServiceClass(HelloServiceImpl.class);
        factoryUnsecured.setAddress(addressUnsecured);
        factoryUnsecured.create();
        System.out.println("Endpoint NON SÉCURISÉ démarré. WSDL: " + addressUnsecured + "?wsdl");

        // --- Endpoint 2: SÉCURISÉ (requiert UsernameToken) ---
        String addressSecured = "http://localhost:8080/services/hello-secure";
        JaxWsServerFactoryBean factorySecured = new JaxWsServerFactoryBean();
        factorySecured.setServiceClass(HelloServiceImpl.class);
        factorySecured.setAddress(addressSecured);

        // 1. Définir les paramètres WSS4J
        Map<String, Object> securityProps = new HashMap<>();
        // Indiquer à l'intercepteur IN de vérifier le UsernameToken
        securityProps.put(WSConstants.ACTION, WSConstants.USERNAME_TOKEN);
        // Fournir la classe qui va valider le mot de passe
        securityProps.put(WSConstants.PW_CALLBACK_CLASS, ServerPasswordCallback.class.getName());

        // 2. Créer l'intercepteur IN (entrant)
        WSS4JInInterceptor securityInterceptor = new WSS4JInInterceptor(securityProps);

        // 3. Lier l'intercepteur au serveur
        factorySecured.getInInterceptors().add(securityInterceptor);

        factorySecured.create();
        System.out.println("Endpoint SÉCURISÉ démarré. WSDL: " + addressSecured + "?wsdl");

        // Empêche le programme de se terminer immédiatement
        try {
            System.out.println("\nServeurs actifs. Appuyez sur Ctrl+C pour arrêter.");
            Thread.sleep(60 * 60 * 1000); // Maintient le serveur actif pendant 1h
        } catch (InterruptedException e) {
            // En cas d'interruption
        }
    }
}