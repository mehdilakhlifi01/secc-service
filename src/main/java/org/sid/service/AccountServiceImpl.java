package org.sid.service;

import org.sid.dao.AppRoleRepository;
import org.sid.dao.AppUserRepository;
import org.sid.entites.AppRole;
import org.sid.entites.AppUser;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

@Service
@Transactional
public class AccountServiceImpl implements AccountService {

    private AppUserRepository appUserRepository;
    private AppRoleRepository appRoleRepository;
    private BCryptPasswordEncoder bCryptPasswordEncoder;

    public AccountServiceImpl(AppUserRepository appUserRepository, AppRoleRepository appRoleRepository, BCryptPasswordEncoder bCryptPasswordEncoder) {
        this.appUserRepository = appUserRepository;
        this.appRoleRepository = appRoleRepository;

        this.bCryptPasswordEncoder = bCryptPasswordEncoder;
    }


    @Override
    public AppUser saveUser(String username, String password, String confirmed) {

     AppUser user= appUserRepository.findByUsername(username);
     if(user!=null) throw new RuntimeException("user deja exist");
     if(!password.equals(confirmed)) throw new RuntimeException("Please confirm your password");
     AppUser appUser=new AppUser();
     appUser.setUsername(username);
     appUser.setPassword(bCryptPasswordEncoder.encode(password));
     appUser.setActived(true);
     appUserRepository.save(appUser);

        addRoleToUser(username,"USER");



        return appUser;
    }

    @Override
    public AppRole save(AppRole role) {


        return appRoleRepository.save(role);
    }

    @Override
    public AppUser loadUserByUsername(String username) {


        return appUserRepository.findByUsername(username);
    }

    @Override
    public void addRoleToUser(String username, String rolename) {

      AppUser appUser= appUserRepository.findByUsername(username);
      AppRole appRole=appRoleRepository.findByRoleName(rolename);
      appUser.getRoles().add(appRole);

    }
}
