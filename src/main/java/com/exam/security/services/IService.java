package com.exam.security.services;

import com.exam.security.entities.AppRole;
import com.exam.security.entities.AppUser;
import java.util.List;

public interface IService {
    AppUser addUser(AppUser appUser);
    AppRole addRole(AppRole appRole);
    void addRoleToUser(String nameRole, String nameUser);
    AppUser findUserByUsername(String username);
    List<AppUser> listUser();

}
