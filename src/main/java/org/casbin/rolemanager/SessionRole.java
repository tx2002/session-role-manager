// Copyright 2024 The casbin Authors. All Rights Reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package org.casbin.rolemanager;

import java.util.ArrayList;
import java.util.List;

public class SessionRole {
    private String name;
    private List<Session> sessions;

    public SessionRole(String name) {
        this.name = name;
        this.sessions = new ArrayList<>();
    }

    public String getName() {
        return name;
    }

    public void addSession(Session session) {
        this.sessions.add(session);
    }

    public void deleteSessions(String sessionName) {
        sessions.removeIf(s -> s.getRole().getName().equals(sessionName));
    }

    public List<String> getSessionRoles(String requestTime) {
        List<String> roles = new ArrayList<>();
        for (Session session : sessions) {
            if (session.getStartTime().compareTo(requestTime) <= 0 && session.getEndTime().compareTo(requestTime) >= 0) {
                if (!roles.contains(session.getRole().getName())) {
                    roles.add(session.getRole().getName());
                }
            }
        }
        return roles;
    }

    public boolean hasValidSession(String roleName, int hierarchyLevel, String requestTime) {
        if (hierarchyLevel == 1) {
            return this.name.equals(roleName);
        }

        for (Session session : sessions) {
            if (session.getStartTime().compareTo(requestTime) <= 0 && session.getEndTime().compareTo(requestTime) >= 0) {
                if (session.getRole().getName().equals(roleName)) {
                    return true;
                }
                if (session.getRole().hasValidSession(roleName, hierarchyLevel - 1, requestTime)) {
                    return true;
                }
            }
        }
        return false;
    }

    public boolean hasDirectRole(String roleName, String requestTime) {
        for (Session session : sessions) {
            if (session.getRole().getName().equals(roleName) &&
                    session.getStartTime().compareTo(requestTime) <= 0 &&
                    session.getEndTime().compareTo(requestTime) >= 0) {
                return true;
            }
        }
        return false;
    }

    @Override
    public String toString() {
        StringBuilder sb = new StringBuilder(name + " < ");
        for (int i = 0; i < sessions.size(); i++) {
            if (i > 0) sb.append(", ");
            sb.append(sessions.get(i).getRole().getName())
                    .append(" (until: ").append(sessions.get(i).getEndTime()).append(")");
        }
        return sb.toString();
    }
}
