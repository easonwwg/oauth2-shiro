package com.monkeyk.os.domain.users;

import java.util.List;

/**
 * 2016/6/3
 * 用户服务的仓储
 * @author Shengzhao Li
 */

public interface UsersAuthzRepository extends UsersRepository {

    List<Users> findUsersByUsername(String username);

    List<Roles> findAvailableRolesList();

    Users findByUsername(String username);

    int saveUsers(Users users);

    Roles findRolesByGuid(String guid);

    void insertUserRoles(int userId, int rolesId);
}