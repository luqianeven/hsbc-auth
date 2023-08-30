package com.hsbc.security.service;


public class ApiResult<T> {
    State state;
    T data;
    String msg;
    ApiResult(State state, T data, String msg) {
        this.state = state;
        this.data = data;
        this.msg = msg;
    }

    public State getState() {
        return state;
    }

    public void setState(State state) {
        this.state = state;
    }

    public Object getData() {
        return data;
    }

    public void setData(T data) {
        this.data = data;
    }

    public String getMsg() {
        return msg;
    }

    public void setMsg(String msg) {
        this.msg = msg;
    }
}

enum State {
    OK("ok"),
    ERROR("error");
    String value;
    State(String name) {
        this.value = name;
    }

    public String getValue() {
        return value;
    }
}
