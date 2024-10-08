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

import org.casbin.jcasbin.rbac.RoleManager;
import java.util.*;

/**
 * SessionRoleManager is an implementation of the RoleManager interface that supports temporal role inheritance
 * using sessions with a defined start and end time for role inheritance.
 */
public class SessionRoleManager implements RoleManager {
    private Map<String, SessionRole> allRoles; // Stores all roles with their respective session information
    private int maxHierarchyLevel; // Maximum allowed hierarchy level for role inheritance

    /**
     * Constructor for creating an instance of SessionRoleManager.
     *
     * @param maxHierarchyLevel The maximum depth of role hierarchy.
     */
    public SessionRoleManager(int maxHierarchyLevel) {
        this.allRoles = new HashMap<>();
        this.maxHierarchyLevel = maxHierarchyLevel;
    }

    /**
     * Checks if a role exists in the manager.
     *
     * @param name Name of the role.
     * @return True if the role exists, false otherwise.
     */
    private boolean hasRole(String name) {
        return allRoles.containsKey(name);
    }

    /**
     * Creates a new role if it doesn't already exist.
     *
     * @param name Name of the role.
     * @return The created or existing role.
     */
    private SessionRole createRole(String name) {
        if (!hasRole(name)) {
            allRoles.put(name, new SessionRole(name));
        }
        return allRoles.get(name);
    }

    /**
     * Clears all stored roles and resets the manager.
     */
    @Override
    public void clear() {
        allRoles.clear();
    }

    /**
     * Adds an inheritance link between two roles, valid for a specific time range.
     *
     * @param name1     Name of the first role (child role).
     * @param name2     Name of the second role (parent role).
     * @param timeRange The time range (start time, end time) for when the link is active.
     * @throws IllegalArgumentException if the time range is not exactly 2 elements.
     */
    @Override
    public void addLink(String name1, String name2, String... timeRange) {
        if (timeRange.length != 2) {
            throw new IllegalArgumentException("Time range must consist of start and end times.");
        }
        String startTime = timeRange[0];
        String endTime = timeRange[1];

        SessionRole role1 = createRole(name1);
        SessionRole role2 = createRole(name2);

        Session session = new Session(role2, startTime, endTime);
        role1.addSession(session);
    }

    /**
     * Deletes the inheritance link between two roles.
     *
     * @param name1 Name of the first role (child role).
     * @param name2 Name of the second role (parent role).
     */
    @Override
    public void deleteLink(String name1, String name2, String... unused) {
        if (!hasRole(name1) || !hasRole(name2)) {
            throw new IllegalArgumentException("Role not found: " + name1 + " or " + name2);
        }

        SessionRole role1 = createRole(name1);
        role1.deleteSessions(name2);
    }

    /**
     * Checks if a role inherits another role at a specific time.
     *
     * @param name1       Name of the first role (child role).
     * @param name2       Name of the second role (parent role).
     * @param requestTime The time to check the role inheritance.
     * @return True if role1 inherits role2 at the given time, false otherwise.
     */
    @Override
    public boolean hasLink(String name1, String name2, String... requestTime) {
        if (requestTime.length != 1) {
            throw new IllegalArgumentException("Request time must be specified.");
        }
        if (name1.equals(name2)) {
            return true;
        }

        if (!hasRole(name1) || !hasRole(name2)) {
            return false;
        }

        SessionRole role1 = createRole(name1);
        return role1.hasValidSession(name2, maxHierarchyLevel, requestTime[0]);
    }

    /**
     * Gets all roles that a role inherits at a specific time.
     *
     * @param name        The name of the role.
     * @param currentTime The current time to check the role inheritance.
     * @return A list of roles that the role inherits at the given time.
     */
    @Override
    public List<String> getRoles(String name, String... currentTime) {
        if (currentTime.length != 1) {
            throw new IllegalArgumentException("Current time must be specified.");
        }
        String requestTime = currentTime[0];

        if (!hasRole(name)) {
            throw new IllegalArgumentException("Role not found: " + name);
        }

        return createRole(name).getSessionRoles(requestTime);
    }

    /**
     * Gets all users that inherit a specific role at a given time.
     *
     * @param name        The name of the role to check.
     * @param currentTime The current time to check the role inheritance.
     * @return A list of users that inherit the given role at the specified time.
     */
    @Override
    public List<String> getUsers(String name, String... currentTime) {
        if (currentTime.length != 1) {
            throw new IllegalArgumentException("Current time must be specified.");
        }
        String requestTime = currentTime[0];

        List<String> users = new ArrayList<>();
        for (SessionRole role : allRoles.values()) {
            if (role.hasDirectRole(name, requestTime)) {
                users.add(role.getName());
            }
        }
        Collections.sort(users);
        return users;
    }

    /**
     * Prints all the roles and their sessions.
     */
    @Override
    public void printRoles() {
        allRoles.values().forEach(role -> System.out.println(role.toString()));
    }
}
