package org.sid.service;

import org.sid.entites.AppRole;
import org.sid.entites.AppUser;

public interface AccountService {

    public AppUser saveUser(String username, String password, String confirmed);
    public AppRole save(AppRole role);
    public AppUser loadUserByUsername(String username);
    public void addRoleToUser(String username,String rolename);



}
