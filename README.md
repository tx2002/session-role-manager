# session-role-manager
[![codebeat badge](https://codebeat.co/badges/998c8e12-ffdd-4196-b2a2-8979d7f1ee8a)](https://codebeat.co/projects/github-com-jcasbin-session-role-manager-master)
[![build](https://github.com/jcasbin/session-role-manager/actions/workflows/ci.yml/badge.svg)](https://github.com/jcasbin/session-role-manager/actions)
[![codecov](https://codecov.io/github/jcasbin/session-role-manager/branch/master/graph/badge.svg?token=4YRFEQY7VK)](https://codecov.io/github/jcasbin/session-role-manager)
[![javadoc](https://javadoc.io/badge2/org.casbin/session-role-manager/javadoc.svg)](https://javadoc.io/doc/org.casbin/session-role-manager)
[![Maven Central](https://img.shields.io/maven-central/v/org.casbin/session-role-manager.svg)](https://mvnrepository.com/artifact/org.casbin/session-role-manager/latest)
[![Discord](https://img.shields.io/discord/1022748306096537660?logo=discord&label=discord&color=5865F2)](https://discord.gg/S5UjpzGZjN)

Session Role Manager is the [Session-based](https://en.wikipedia.org/wiki/Session_(computer_science)) role manager for [jCasbin](https://github.com/casbin/jcasbin). With this library, jCasbin can load session-based role hierarchy (user-role mapping) from jCasbin policy or save role hierarchy to it. The session is only active in the specified time range.

## Installation
```xml
<dependency>
    <groupId>org.casbin</groupId>
    <artifactId>session-role-manager</artifactId>
    <version>1.0.0</version>
</dependency>
```

## Example
```java
import org.casbin.jcasbin.main.Enforcer;
import org.casbin.jcasbin.persist.file_adapter.FileAdapter;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

public class Example {
    public static void main(String[] args) {
        // Create a new Enforcer using the model path. The default role manager is used initially.
        Enforcer e = new Enforcer("examples/rbac_model_with_sessions.conf");

        // Manually set an adapter for the policy.
        FileAdapter a = new FileAdapter("examples/rbac_policy_with_sessions.csv");
        e.setAdapter(a);

        // Use our custom role manager.
        SessionRoleManager rm = new SessionRoleManager(10);
        e.setRoleManager(rm);

        // If our role manager relies on Casbin policy (e.g., reading "g" policy rules),
        // we need to set the role manager before loading the policy.
        e.loadPolicy();

        // Current role inheritance tree (Time ranges shown in parentheses):
        //          delta          echo          foxtrott
        //             \            / \           /
        //      (0-20)  \   (5-15) /   \ (10-20) / (10-12)
        //               \        /     \       /
        //                 bravo         charlie
        //                   \             /
        //             (0-10) \           / (5-15)
        //                     \         /
        //                        alpha

        // Test permissions for different time points
        assertTrue(e.enforce("alpha", "data1", "read", "00"));
        assertTrue(e.enforce("alpha", "data1", "read", "05"));
        assertTrue(e.enforce("alpha", "data1", "read", "10"));
        assertFalse(e.enforce("alpha", "data1", "read", "15"));
        assertFalse(e.enforce("alpha", "data1", "read", "20"));

        assertFalse(e.enforce("alpha", "data2", "read", "00"));
        assertTrue(e.enforce("alpha", "data2", "read", "05"));
        assertTrue(e.enforce("alpha", "data2", "read", "10"));
        assertTrue(e.enforce("alpha", "data2", "read", "15"));
        assertFalse(e.enforce("alpha", "data2", "read", "20"));

        assertFalse(e.enforce("alpha", "data3", "read", "00"));
        assertFalse(e.enforce("alpha", "data3", "read", "05"));
        assertTrue(e.enforce("alpha", "data3", "read", "10"));
        assertFalse(e.enforce("alpha", "data3", "read", "15"));
        assertFalse(e.enforce("alpha", "data3", "read", "20"));
    }
}

```