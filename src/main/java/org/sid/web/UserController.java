package org.sid.web;

import lombok.Data;
import org.sid.entites.AppUser;
import org.sid.service.AccountService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class UserController {

    @Autowired
    AccountService accountService;

    @PostMapping("/register")
    public AppUser register(@RequestBody UserForm username){

        return accountService.saveUser(username.getUsername(),username.getPassword(),username.getConfirmed());

    }




}
@Data
class UserForm{
    private String username;
    private String password;
    private String confirmed;
}
