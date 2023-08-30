package com.hsbc.security.service;

import com.hsbc.security.entity.Token;
import com.hsbc.security.util.TokenUtil;
import org.junit.Before;
import org.junit.BeforeClass;
import org.junit.Test;

import java.util.Collections;
import java.util.Set;

import static junit.framework.TestCase.assertEquals;
import static junit.framework.TestCase.assertTrue;

public class TokenUtilTest {
    Set<String> roles = new java.util.HashSet<>();
    @Test
    public void testSerialize() {
        roles.add("admin");
        Token token = new Token("user", roles, System.currentTimeMillis() + CredentialService.EXPIRE_THRESHOLD);
        String tokenStr = TokenUtil.serialize(token);
        assertTrue(tokenStr.length() > 0);
    }

    @Test
    public void testDeserialize() {
        roles.add("admin");
        String tokenStr = "rO0ABXNyAB5jb20uaHNiYy5zZWN1cml0eS5lbnRpdHkuVG9rZW4H1J2pDg5udgIAA0oABmV4cGlyZUwABXJvbGVzdAAPTGphdmEvdXRpbC9TZXQ7TAAIdXNlck5hbWV0ABJMamF2YS9sYW5nL1N0cmluZzt4cAAAAYpE2-cTc3IAEWphdmEudXRpbC5IYXNoU2V0ukSFlZa4tzQDAAB4cHcMAAAAED9AAAAAAAABdAAFYWRtaW54dAAEdXNlcg";
        Token token = TokenUtil.deserialize(tokenStr);
        assertEquals("user", token.getUserName());
        assertTrue(token.getRoles().containsAll(roles) && roles.containsAll(token.getRoles()));
        assertEquals(1693372376851L, token.getExpire());
    }
}
