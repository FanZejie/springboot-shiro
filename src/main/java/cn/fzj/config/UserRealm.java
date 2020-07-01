package cn.fzj.config;

import cn.fzj.pojo.User;
import cn.fzj.service.UserService;
import org.apache.shiro.SecurityUtils;
import org.apache.shiro.authc.*;
import org.apache.shiro.authz.AuthorizationInfo;
import org.apache.shiro.authz.SimpleAuthorizationInfo;
import org.apache.shiro.realm.AuthorizingRealm;
import org.apache.shiro.session.Session;
import org.apache.shiro.subject.PrincipalCollection;
import org.apache.shiro.subject.Subject;
import org.springframework.beans.factory.annotation.Autowired;

/**
 * @author Mike
 * 自定义的realm
 */
public class UserRealm extends AuthorizingRealm {
    @Autowired
    UserService userService;
    @Override
    protected AuthorizationInfo doGetAuthorizationInfo(PrincipalCollection principalCollection) {
        System.out.println("执行了=>授权doGetAuthorizationInfo");
        SimpleAuthorizationInfo info = new SimpleAuthorizationInfo();

        //info.addStringPermission("user:add");
        //拿到当前登录的这个对象
        Subject subject = SecurityUtils.getSubject();
        User currentUser = (User) subject.getPrincipal();//拿到user对象
        info.addStringPermission(currentUser.getPerms());//设置当前用户的权限
        return info;
    }

    @Override
    protected AuthenticationInfo doGetAuthenticationInfo(AuthenticationToken authenticationToken) throws AuthenticationException {
        System.out.println("执行了=>授权doGetAuthorizationInfo");

        UsernamePasswordToken userToken = (UsernamePasswordToken) authenticationToken;
        //认证用户名，密码，数据库中取
        User user = userService.queryUserByName(userToken.getUsername());
        if (user==null){//用户为空，没找到
            return null;//会抛出一个异常
        }
        Subject currentSubject = SecurityUtils.getSubject();
        Session session = currentSubject.getSession();
        session.setAttribute("loginUser",user);//这会登陆成功就存到session
        //关于密码的认证由shiro自己做
        return new SimpleAuthenticationInfo(user,user.getPwd(),"");
    }
}
