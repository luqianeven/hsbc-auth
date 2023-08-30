package com.hsbc.security.entity;

import java.io.Serializable;
import java.util.Set;

public class Token implements Serializable {
    String userName;
    Set<String> roles;
    long expire;

    public String getUserName() {
        return userName;
    }

    public Set<String> getRoles() {
        return roles;
    }

    public long getExpire() {
        return expire;
    }

    public void setUserName(String userName) {
        this.userName = userName;
    }

    public void setRoles(Set<String> roles) {
        this.roles = roles;
    }

    public void setExpire(long expire) {
        this.expire = expire;
    }

    public Token(String userName, Set<String> roles, long expire) {
        this.userName = userName;
        this.roles = roles;
        this.expire = expire;
    }

}
