package org.casbin.rolemanager;

public class Session {
    private SessionRole role;
    private String startTime;
    private String endTime;

    public Session(SessionRole role, String startTime, String endTime) {
        this.role = role;
        this.startTime = startTime;
        this.endTime = endTime;
    }

    public SessionRole getRole() {
        return role;
    }

    public String getStartTime() {
        return startTime;
    }

    public String getEndTime() {
        return endTime;
    }
}
