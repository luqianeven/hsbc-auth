package com.hsbc.security.service;

import com.hsbc.security.util.MessageDict;
import org.junit.Before;
import org.junit.Test;

import java.io.UnsupportedEncodingException;
import java.util.HashSet;
import java.util.Set;

import static junit.framework.TestCase.assertEquals;
import static org.junit.Assert.assertTrue;

public class CredentialServiceTest {
    CredentialService ss = CredentialService.getInstance();

    @Before
    public void setup() {
        ss.clear();
    }

    @Test
    public void testCreateUser() {
        ApiResult result = ss.createUser("test", "12345");
        assertEquals(State.OK, result.getState());

        // empty username test case
        result = ss.createUser("", "34567");
        assertEquals(State.ERROR, result.getState());
        assertEquals(MessageDict.INPUT_EMPTY, result.getMsg());

        // empty password test case
        result = ss.createUser("user", "");
        assertEquals(State.ERROR, result.getState());
        assertEquals(MessageDict.INPUT_EMPTY, result.getMsg());

        // user exist test case
        result = ss.createUser("test", "12345");
        assertEquals(State.ERROR, result.getState());
        assertEquals(MessageDict.USER_EXIST, result.getMsg());
    }

    @Test
    public void testDeleteUser() {
        ss.createUser("test", "12345");
        ApiResult result = ss.deleteUser("test");
        assertEquals(State.OK, result.getState());

        // empty username test case
        result = ss.deleteUser("");
        assertEquals(State.ERROR, result.getState());
        assertEquals(MessageDict.INPUT_EMPTY, result.getMsg());

        // user not exist test case
        result = ss.deleteUser("user");
        assertEquals(State.ERROR, result.getState());
        assertEquals(MessageDict.USER_NOT_EXIST, result.getMsg());
    }

    @Test
    public void testCreateRole() {
        ApiResult result = ss.createRole("admin");
        assertEquals(State.OK, result.getState());

        // empty role name test case
        result = ss.createRole("");
        assertEquals(State.ERROR, result.getState());
        assertEquals(MessageDict.INPUT_EMPTY, result.getMsg());

        // role exist test case
        result = ss.createRole("admin");
        assertEquals(State.ERROR, result.getState());
        assertEquals(MessageDict.ROLE_EXIST, result.getMsg());
    }

    @Test
    public void testDeleteRole() {
        ss.createRole("admin");
        ApiResult result = ss.deleteRole("admin");
        assertEquals(State.OK, result.getState());

        // empty role name test case
        result = ss.deleteRole("");
        assertEquals(State.ERROR, result.getState());
        assertEquals(MessageDict.INPUT_EMPTY, result.getMsg());

        // role not exist test case
        result = ss.deleteRole("noexitrole");
        assertEquals(State.ERROR, result.getState());
        assertEquals(MessageDict.ROLE_NOT_EXIST, result.getMsg());
    }

    @Test
    public void testAddRoleToUser() {
        ss.createUser("test", "12345");
        ss.createRole("admin");
        ApiResult result = ss.addRoleToUser("test", "admin");
        assertEquals(State.OK, result.getState());

        // empty username test case
        result = ss.addRoleToUser("", "admin");
        assertEquals(State.ERROR, result.getState());
        assertEquals(MessageDict.INPUT_EMPTY, result.getMsg());

        // empty role name test case
        result = ss.addRoleToUser("test", "");
        assertEquals(State.ERROR, result.getState());
        assertEquals(MessageDict.INPUT_EMPTY, result.getMsg());

        // role already exists for the user
        result = ss.addRoleToUser("test", "admin");
        assertEquals(State.OK, result.getState());

        // user doesn't exist
        result = ss.addRoleToUser("noexistuser", "admin");
        assertEquals(State.ERROR, result.getState());
        assertEquals(MessageDict.USER_NOT_EXIST, result.getMsg());

        // role doesn't exist
        result = ss.addRoleToUser("test", "rolenotexist");
        assertEquals(State.ERROR, result.getState());
        assertEquals(MessageDict.ROLE_NOT_EXIST, result.getMsg());
    }

    @Test
    public void testAuthenticate() {
        ss.createUser("test", "12345");
        ss.authorize("test", "12345");
        ApiResult result = ss.authenticate("test", "12345");
        assertEquals(State.OK, result.getState());
        assertTrue(((String)result.getData()).length() > 0);

        // token not exist
        ss.invalidate((String)result.getData());
        result = ss.authenticate("test", "12345");
        assertEquals(State.ERROR, result.getState());
        assertEquals(MessageDict.TOKEN_NOT_EXIST, result.getMsg());

        // empty username test case
        result = ss.authenticate("", "admin");
        assertEquals(State.ERROR, result.getState());
        assertEquals(MessageDict.INPUT_EMPTY, result.getMsg());

        // empty password test case
        result = ss.authenticate("test", "");
        assertEquals(State.ERROR, result.getState());
        assertEquals(MessageDict.INPUT_EMPTY, result.getMsg());

        // user doesn't exist
        result = ss.authenticate("nouser", "12345");
        assertEquals(State.ERROR, result.getState());
        assertEquals(MessageDict.USER_NOT_EXIST, result.getMsg());

        // wrong pwd case
        result = ss.authenticate("test", "wrongpwd");
        assertEquals(State.ERROR, result.getState());
        assertEquals(MessageDict.WRONG_PASSWORD, result.getMsg());
    }

    @Test
    public void invalidate() {
        ss.createUser("admin", "12345");
        ApiResult result = ss.authorize("admin", "12345");
        String token = (String) result.getData();
        result = ss.invalidate(token);
        assertEquals(State.OK, result.getState());

        // empty token test case
        result = ss.invalidate("");
        assertEquals(State.ERROR, result.getState());
        assertEquals(MessageDict.INPUT_EMPTY, result.getMsg());

        result = ss.invalidate(token);
        assertEquals(State.ERROR, result.getState());
        assertEquals(MessageDict.TOKEN_NOT_EXIST, result.getMsg());

        // invalidate an invalid token
        ss.authorize("admin", "12345");
        result = ss.invalidate("rO0ABXNyAB5jb20uaHNiYy5zZWN1cml0eS5lbnRpdHkuVG9rZW4H1J2pDg5udgIAA0oABmV4cGlyZUwABXJvbGVzdAAPTGphdmEvdXRpbC9TZXQ7TAAIdXNlck5hbWV0ABJMamF2YS9sYW5nL1N0cmluZzt4cP__________c3IAEWphdmEudXRpbC5IYXNoU2V0ukSFlZa4tzQDAAB4cHcMAAAAED9AAAAAAAACdAAGbm9ybWFsdAAFYWRtaW54cQB-AAc");
        assertEquals(State.ERROR, result.getState());
        assertEquals(MessageDict.TOKEN_EXPIRE, result.getMsg());
    }

    @Test
    public void testCheckRole() {
        ss.createUser("admin", "12345");
        ss.createRole("admin");
        ss.addRoleToUser("admin", "admin");
        ApiResult authResult = ss.authorize("admin", "12345");
        ApiResult checkRoleResult = ss.checkRole((String)authResult.getData(), "admin");
        assertEquals(State.OK, checkRoleResult.getState());

        // empty token test case
        ApiResult emptyResult = ss.checkRole("", "");
        assertEquals(State.ERROR, emptyResult.getState());
        assertEquals(MessageDict.INPUT_EMPTY, emptyResult.getMsg());

        // valid role doesn't exist in token
        ss.createRole("role-not-in-token");
        checkRoleResult = ss.checkRole((String)authResult.getData(), "role-not-in-token");
        assertEquals(State.OK, checkRoleResult.getState());

        // invalid role check
        checkRoleResult  = ss.checkRole((String)authResult.getData(), "notexist");
        assertEquals(State.ERROR, checkRoleResult.getState());
        assertEquals(MessageDict.ROLE_NOT_EXIST, checkRoleResult.getMsg());

        // invalid token check
        checkRoleResult  = ss.checkRole("12345", "admin");
        assertEquals(State.ERROR, checkRoleResult.getState());
        assertEquals(MessageDict.INVALID_TOKEN, checkRoleResult.getMsg());

        // expire token case
        checkRoleResult  = ss.checkRole("rO0ABXNyAB5jb20uaHNiYy5zZWN1cml0eS5lbnRpdHkuVG9rZW4H1J2pDg5udgIAA0oABmV4cGlyZUwABXJvbGVzdAAPTGphdmEvdXRpbC9TZXQ7TAAIdXNlck5hbWV0ABJMamF2YS9sYW5nL1N0cmluZzt4cP__________c3IAEWphdmEudXRpbC5IYXNoU2V0ukSFlZa4tzQDAAB4cHcMAAAAED9AAAAAAAACdAAGbm9ybWFsdAAFYWRtaW54cQB-AAc", "admin");
        assertEquals(State.ERROR, checkRoleResult.getState());
        assertEquals(MessageDict.TOKEN_EXPIRE, checkRoleResult.getMsg());

        // user haven't setup any role
        ss.createUser("norole", "12345");
        ss.createRole("somerole");
        checkRoleResult = ss.authorize("norole", "12345");
        checkRoleResult = ss.checkRole((String)checkRoleResult.getData(), "somerole");
        assertEquals(State.ERROR, checkRoleResult.getState());
        assertEquals(MessageDict.NO_ROLE_FOR_USER, checkRoleResult.getMsg());
    }

    @Test
    public void testGetAllRoles() {
        ss.createUser("test", "12345");
        ss.createRole("admin");
        ss.createRole("normal");
        ss.addRoleToUser("test", "admin");
        ss.addRoleToUser("test", "normal");

        ApiResult authResult = ss.authorize("test", "12345");
        ApiResult allRoleResult = ss.getAllRoles((String)authResult.getData());
        Set<String> roles = new HashSet<>();
        roles.add("normal");
        roles.add("admin");
        assertEquals(State.OK, authResult.getState());
        assertTrue(((HashSet)allRoleResult.getData()).containsAll(roles) && roles.containsAll((HashSet)allRoleResult.getData()));

        // empty token test case
        ApiResult emptyResult = ss.getAllRoles("");
        assertEquals(State.ERROR, emptyResult.getState());
        assertEquals(MessageDict.INPUT_EMPTY, emptyResult.getMsg());

        // invalid token test case
        allRoleResult = ss.getAllRoles("12345");
        assertEquals(State.ERROR, allRoleResult.getState());
        assertEquals(MessageDict.INVALID_TOKEN, allRoleResult.getMsg());

        // token expire case
        allRoleResult = ss.getAllRoles("rO0ABXNyAB5jb20uaHNiYy5zZWN1cml0eS5lbnRpdHkuVG9rZW4H1J2pDg5udgIAA0oABmV4cGlyZUwABXJvbGVzdAAPTGphdmEvdXRpbC9TZXQ7TAAIdXNlck5hbWV0ABJMamF2YS9sYW5nL1N0cmluZzt4cP__________c3IAEWphdmEudXRpbC5IYXNoU2V0ukSFlZa4tzQDAAB4cHcMAAAAED9AAAAAAAACdAAGbm9ybWFsdAAFYWRtaW54cQB-AAc");
        assertEquals(State.ERROR, allRoleResult.getState());
        assertEquals(MessageDict.TOKEN_EXPIRE, allRoleResult.getMsg());


    }
}