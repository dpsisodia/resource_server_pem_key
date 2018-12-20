package org.eso.oauth.resource.server;

import java.security.KeyFactory;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.X509EncodedKeySpec;
import java.util.HashMap;
import java.util.Map;
import java.util.Map.Entry;

import org.apache.commons.codec.binary.Base64;
import org.springframework.security.oauth2.common.exceptions.InvalidTokenException;
import org.springframework.security.oauth2.provider.token.store.JwtAccessTokenConverter;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jws;
import io.jsonwebtoken.Jwts;

public class MyJwtAccessTokenConverter extends JwtAccessTokenConverter {
	
	private String verifierKey;
	
    public void setVerifierKey(String publicKey) {
    	this.verifierKey = publicKey;
    }
    
    @Override
    protected Map<String, Object> decode(String token) {
        try {
        	token = token.replaceAll("%3D", "=");
        	Jws<Claims> claims = Jwts.parser().setSigningKey(loadRSAPublicKey(verifierKey)).parseClaimsJws(token);
        	Map<String, Object> map = new HashMap();
        	for(Entry<String, Object> es:claims.getBody().entrySet()) {
        		//jwt attribute expiry is int in Spring code base  
        		if (es.getKey().equalsIgnoreCase(EXP) && es.getValue() instanceof Integer) {
    				map.put(EXP, new Long((Integer) es.getValue()));
    			} else {
    				map.put(es.getKey(), es.getValue());
    				//mapping to other attributes
    				if(es.getKey().equalsIgnoreCase("roles"))
    					map.put("authorities", es.getValue());
    				if(es.getKey().equalsIgnoreCase("sub"))
    					map.put("user_name", es.getValue());
    				
    			}
        	}
        	
            return map;
        }
        catch (Exception e) {
            throw new InvalidTokenException("Cannot convert access token to JSON. "+e.getMessage(), e);
        }
    }
    
    public RSAPublicKey loadRSAPublicKey(String publicKeyPEM) throws Exception{
 	   // decode to its constituent bytes
     publicKeyPEM = publicKeyPEM.replace("-----BEGIN PUBLIC KEY-----", "");
     publicKeyPEM = publicKeyPEM.replace("-----END PUBLIC KEY-----", "");
     byte[] publicKeyBytes = Base64.decodeBase64(publicKeyPEM);

     // create a key object from the bytes
     X509EncodedKeySpec keySpec = new X509EncodedKeySpec(publicKeyBytes);
     KeyFactory keyFactory;
		try {
			keyFactory = KeyFactory.getInstance("RSA");
			return (RSAPublicKey) keyFactory.generatePublic(keySpec);
		} catch (Exception e) {
			throw new Exception("Fail to create RSAPublicKey", e);
		}
    }

}