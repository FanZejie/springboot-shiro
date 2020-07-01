package cn.fzj.mapper;

import cn.fzj.pojo.User;
import org.apache.ibatis.annotations.Mapper;
import org.springframework.stereotype.Repository;


/**
 * @author Mike
 */
@Repository
@Mapper
public interface UserMapper {
    public User queryUserByName(String name);
}
