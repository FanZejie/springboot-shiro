package cn.fzj.service;

import cn.fzj.pojo.User;
import org.springframework.stereotype.Service;

/**
 * @author Mike
 */
public interface UserService {
    public User queryUserByName(String name);
}
