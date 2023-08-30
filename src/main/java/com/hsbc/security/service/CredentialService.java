package com.hsbc.security.service;

import com.hsbc.security.entity.Role;
import com.hsbc.security.entity.Token;
import com.hsbc.security.entity.User;
import com.hsbc.security.util.MessageDict;
import com.hsbc.security.util.StringUtil;
import com.hsbc.security.util.TokenUtil;

import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import java.util.stream.Collectors;

public class CredentialService {
    public static final long EXPIRE_THRESHOLD = 2 * 60 * 60 * 1000;
    private static CredentialService instance = new CredentialService();

    private Map<String, Role> roles = new ConcurrentHashMap<>();
    private Map<String, User> users = new ConcurrentHashMap<>();
    private Map<String, Token> tokens = new ConcurrentHashMap<>();
    private Map<String, String> tokenCache = new LinkedHashMap<>();

    private CredentialService() {
    }

    private static class ServiceHolder {
        private static final CredentialService instance = new CredentialService();
    }

    public static CredentialService getInstance() {
        return ServiceHolder.instance;
    }


    public ApiResult createUser(String userName, String password) {
        if (StringUtil.isEmpty(userName) || StringUtil.isEmpty(password)) {
            return new ApiResult(State.ERROR, null, MessageDict.INPUT_EMPTY);
        }
        if (users.containsKey(userName)) {
            return new ApiResult(State.ERROR, null, MessageDict.USER_EXIST);
        }
        users.put(userName, new User(userName, StringUtil.hash(password)));
        return new ApiResult(State.OK, true, MessageDict.USER_ADDED);
    }

    public ApiResult deleteUser(String userName) {
        if (StringUtil.isEmpty(userName)) {
            return new ApiResult(State.ERROR, null, MessageDict.INPUT_EMPTY);
        }
        if (users.containsKey(userName)) {
            users.remove(userName);
            if (tokens.containsKey(userName)) {
                tokens.remove(userName);
            }
            return new ApiResult(State.OK, true, MessageDict.USER_DELETED);
        }
        return new ApiResult(State.ERROR, null, MessageDict.USER_NOT_EXIST);
    }

    public ApiResult createRole(String roleName) {
        if (StringUtil.isEmpty(roleName)) {
            return new ApiResult(State.ERROR, null, MessageDict.INPUT_EMPTY);
        }
        if (roles.containsKey(roleName)) {
            return new ApiResult(State.ERROR, null, MessageDict.ROLE_EXIST);
        }
        roles.put(roleName, new Role(roleName));
        return new ApiResult(State.OK, true, MessageDict.ROLE_CREATED);
    }

    public ApiResult deleteRole(String roleName) {
        if (StringUtil.isEmpty(roleName)) {
            return new ApiResult(State.ERROR, null, MessageDict.INPUT_EMPTY);
        }
        if (roles.containsKey(roleName)) {
            roles.remove(roleName);
            return new ApiResult(State.OK, true, MessageDict.ROLE_DELETED);
        }
        return new ApiResult(State.ERROR, null, MessageDict.ROLE_NOT_EXIST);
    }

    public ApiResult addRoleToUser(String userName, String role) {
        if (StringUtil.isEmpty(userName) || StringUtil.isEmpty(role)) {
            return new ApiResult(State.ERROR, null, MessageDict.INPUT_EMPTY);
        }
        User user = users.get(userName);
        if (user == null) {
            return new ApiResult(State.ERROR, null, MessageDict.USER_NOT_EXIST);
        }
        if (!roles.containsKey(role)) {
            return new ApiResult(State.ERROR, null, MessageDict.ROLE_NOT_EXIST);
        }
        Set<Role> roles = user.getRoles();
        if (roles == null) {
            user.setRoles(new HashSet<>());
        }
        user.getRoles().add(new Role(role));
        return new ApiResult(State.OK, null, MessageDict.ROLE_ADDED);
    }

    public ApiResult authorize(String userName, String password) {
        if (StringUtil.isEmpty(userName) || StringUtil.isEmpty(password)) {
            return new ApiResult(State.ERROR, null, MessageDict.INPUT_EMPTY);
        }
        User user = users.get(userName);
        if (user == null) {
            return new ApiResult(State.ERROR, null, MessageDict.USER_NOT_EXIST);
        }
        String encryptedPwd = StringUtil.hash(password);
        if (encryptedPwd.equals(user.getPassword())) {
            Token token = new Token(userName, toStrRole(user.getRoles()), System.currentTimeMillis() + EXPIRE_THRESHOLD);
            tokens.put(userName, token);
            String tokenStr = TokenUtil.serialize(token);
            tokenCache.put(tokenStr, userName);
            return new ApiResult(State.OK, tokenStr, MessageDict.AUTHENTICATE_SU);
        } else {
            return new ApiResult(State.ERROR, null, MessageDict.WRONG_PASSWORD);
        }
    }

    public ApiResult authenticate(String userName, String password) {
        if (StringUtil.isEmpty(userName) || StringUtil.isEmpty(password)) {
            return new ApiResult(State.ERROR, null, MessageDict.INPUT_EMPTY);
        }
        User user = users.get(userName);
        if (user == null) {
            return new ApiResult(State.ERROR, null, MessageDict.USER_NOT_EXIST);
        }
        String encryptedPwd = StringUtil.hash(password);
        if (encryptedPwd.equals(user.getPassword())) {
            if (!tokens.containsKey(userName)) {
                return new ApiResult(State.ERROR, null, MessageDict.TOKEN_NOT_EXIST);
            } else {
                if (tokens.get(userName).getExpire() > System.currentTimeMillis()) {
                    String toknStr = TokenUtil.serialize(tokens.get(userName));
                    return new ApiResult(State.OK, toknStr, MessageDict.AUTHENTICATE_SU);
                } else {
                    // May consider refresh token
                    return new ApiResult(State.ERROR, null, MessageDict.TOKEN_EXPIRE);
                }
            }
        } else {
            return new ApiResult(State.ERROR, null, MessageDict.WRONG_PASSWORD);
        }
    }

    public ApiResult invalidate(String tokenStr) {
        if (StringUtil.isEmpty(tokenStr)) {
            return new ApiResult(State.ERROR, null, MessageDict.INPUT_EMPTY);
        }

        Token token = extractToken(tokenStr);
        if (token == null) {
            return new ApiResult(State.ERROR, null, MessageDict.INVALID_TOKEN);
        }

        String userName = token.getUserName();
        if (tokens.containsKey(userName)) {
            if (token.getExpire() > System.currentTimeMillis()) {
                tokens.remove(userName);
                return new ApiResult(State.OK, null, MessageDict.INVALIDATE_SU);
            } else {
                return new ApiResult(State.ERROR, null, MessageDict.TOKEN_EXPIRE);
            }
        } else {
            return new ApiResult(State.ERROR, null, MessageDict.TOKEN_NOT_EXIST);
        }
    }

    public ApiResult checkRole(String tokenStr, String role) {
        if (StringUtil.isEmpty(tokenStr) || StringUtil.isEmpty(role)) {
            return new ApiResult(State.ERROR, null, MessageDict.INPUT_EMPTY);
        }
        Token token = extractToken(tokenStr);
        if (token == null) {
            return new ApiResult(State.ERROR, null, MessageDict.INVALID_TOKEN);
        }

        if (!roles.containsKey(role)) {
            return new ApiResult(State.ERROR, null, MessageDict.ROLE_NOT_EXIST);
        }
        if (token.getRoles() == null || token.getRoles().isEmpty()) {
            return new ApiResult(State.ERROR, null, MessageDict.NO_ROLE_FOR_USER);
        }
        if (token.getExpire() < System.currentTimeMillis()) {
            return new ApiResult(State.ERROR, null, MessageDict.TOKEN_EXPIRE);
        }
        if (token.getRoles().contains(role)) {
            return new ApiResult(State.OK, true, MessageDict.ROLE_EXIST_FOR_USER);
        } else {
            return new ApiResult(State.OK, false, MessageDict.ROLE_NOT_EXIST_FOR_USER);
        }
    }

    public ApiResult getAllRoles(String tokenStr) {
        if (StringUtil.isEmpty(tokenStr)) {
            return new ApiResult(State.ERROR, null, MessageDict.INPUT_EMPTY);
        }
        Token token = extractToken(tokenStr);
        if (token == null) {
            return new ApiResult(State.ERROR, null, MessageDict.INVALID_TOKEN);
        }
        if (token.getExpire() < System.currentTimeMillis()) {
            return new ApiResult(State.ERROR, null, MessageDict.TOKEN_EXPIRE);
        }
        return new ApiResult(State.OK, token.getRoles(), MessageDict.ROLE_RETURNED);
    }

    // for test
    void clear() {
        roles.clear();
        users.clear();
        tokens.clear();
    }

    private Set<String> toStrRole(Set<Role> roles) {
        if (roles == null || roles.isEmpty()) {
            return new HashSet<>();
        }
        return roles.stream().map(r -> r.getName()).collect(Collectors.toSet());
    }

    private Token extractToken(String tokenStr) {
        Token token = null;
        if (tokenCache.containsKey(tokenStr)) {
            String userName = tokenCache.getOrDefault(tokenStr, null);
            if (!userName.isEmpty())
                token = tokens.get(userName);
        }
        if (token == null) {
            token = TokenUtil.deserialize(tokenStr);
        }
        return token;
    }

}
