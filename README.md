# Shiro
根据狂神课程学习

## 1.1、什么是Shiro？

-  Apache Shiro是一个强大且易用的Java安全框架 
-  执行身份验证、授权、密码和会话管理 

## 为什么要使用shiro?

如果你是需要设计RBAC（Role Based Access Control）基础系统，需要编写大量用于权限控制的代码时。那么你需要使用Shiro。因为Shiro已经将RBAC系统大量的代码封装好，可以减少我们大量的工作量。

如：页面的显示的**HTML控件**根据登录用户的权限不同而不同。使用Shiro可以轻松解决。

### 有哪些功能？
![](/pictureForReadme/1.png)
### Shiro整体架构

![](/pictureForReadme/3.png)

shiro

1.Authenticator:认证器，管理登陆与登出。

2.Authorizer:授权器，赋予主体权限。

3.Session Manager:session管理器，session管理机制。不借助任何web容器使用session

4.Session Dao:session操作，主要增删改查。

5.Cache Manager:缓存管理器

6.Pluggable Realms(1 or more):shiro与数据库的连接，认证授权校验

7.Cryptography:数据加密，加密算法的实现（SHA、MD5）

8.web Support：对Web项目的支持，Shiro的标签！！

### 访问流程图
![](/pictureForReadme/2.png)
1. 首先应用访问（可以使用远程调用，可以是Web请求等），Shiro通过一个Subject对象来标识当前访问的身份。这句话告诉我们，第一次访问的时候，Shiro肯定会创建一个Subject对象标签当前请求（用户）的身份。
2. SecurityManger容器创建一个Subject对象验证请求的参数，SecurityManager的作用是统一管理Subject。这句话意味着，一个SecurityManager对象管理多个Subject的对象。
3. Subject通过SecurityManger获得操作当前用户的权限，在启动的那一刻，SecurityManger就会加载shiro.ini权限配置文件，在用户登录成功后，可以根据shiro配置的信息，获得用户对应的权限。
4. shiro配置：是一个权限控制信息文件，里面必须包括用户的验证信息，权限的信息
## 快速开始

https://github.com/apache/shiro/blob/master/samples/quickstart/

1.导入日志相关依赖

2.配置文件  log4j.properties

3.快速开始，helloworld

### 快速开始分析：

获取当前用户对象

```java
Subject currentUser = SecurityUtils.getSubject();
```

通过当前用户拿到session

```java
Session session = currentUser.getSession();
```

用户对象的常用方法：

```java
	//判断当前用户是否被认证
	currentUser.isAuthenticated()
	//获得当前用户的一个认证
	currentUser.getPrincipal()
	//当前用户是否拥有xx角色
	currentUser.hasRole("schwartz")
    //已登录用户是否具有某种权限
    currentUser.isPermitted("lightsaber:wield")
```

令牌：

```java
UsernamePasswordToken token = new UsernamePasswordToken("lonestarr", "vespa");
token.setRememberMe(true);//设置记住我功能
currentUser.login(token);//执行登录操作
currentUser.logout();//退出操作
```

## springboot整合shiro

1.先新建一个spring boot的web项目，引入thymeleaf依赖，写好controller，搭建好基础环境，确认能跑起来

2.导入jar包

```xml
<!--shiro整合spring的包-->
        <dependency>
            <groupId>org.apache.shiro</groupId>
            <artifactId>shiro-spring</artifactId>
            <version>1.4.1</version>
        </dependency>
```



3.编写配置类

config->ShiroConfig.java

```java
package cn.fzj.config;

import org.springframework.context.annotation.Configuration;

/**
 * @author Mike
 */
@Configuration
public class ShiroConfig {
    //创建realm对象，需要自定义类
    //DefaultWebSecurityManager
    //shiroFilterFactoryBean
  
}

```

config->UserRealm 继承AuthorizingRealm

用户认证：

```java
package cn.fzj.config;

import org.apache.shiro.authc.AuthenticationException;
import org.apache.shiro.authc.AuthenticationInfo;
import org.apache.shiro.authc.AuthenticationToken;
import org.apache.shiro.authz.AuthorizationInfo;
import org.apache.shiro.realm.AuthorizingRealm;
import org.apache.shiro.subject.PrincipalCollection;

/**
 * @author Mike
 * 自定义的realm
 */
public class UserRealm extends AuthorizingRealm {
    @Override
    protected AuthorizationInfo doGetAuthorizationInfo(PrincipalCollection principalCollection) {
        System.out.println("执行了=>授权doGetAuthorizationInfo");
        return null;
    }

    @Override
    protected AuthenticationInfo doGetAuthenticationInfo(AuthenticationToken authenticationToken) throws AuthenticationException {
        System.out.println("执行了=>认证doGetAuthorizationInfo");
        return null;
    }
}
```

完善ShiroConfig.java

```java
import org.springframework.context.annotation.Configuration;

/**
 * @author Mike
 */
@Configuration
public class ShiroConfig {
    //1.创建realm对象，需要自定义类
    @Bean(name = "userRealm")
    public UserRealm userRealm(){
        return new UserRealm();
    }
    //2.DefaultWebSecurityManager
    @Bean(name="securityManager")
    public DefaultWebSecurityManager getDefaultWebSecurityManager(@Qualifier("userRealm") UserRealm userRealm){
        DefaultWebSecurityManager securityManager = new DefaultWebSecurityManager();
        //关联UserRealm
        securityManager.setRealm(userRealm);
        return securityManager;
    }
    //3.shiroFilterFactoryBean
    @Bean
    public ShiroFilterFactoryBean getShiroFilterFactoryBean(@Qualifier("securityManager") DefaultWebSecurityManager defaultWebSecurityManager){
        ShiroFilterFactoryBean bean = new ShiroFilterFactoryBean();
        //设置安全管理器
        bean.setSecurityManager(defaultWebSecurityManager);
        return bean;
    }
 
}
```



## 登录拦截

写两个页面，页面跳转的请求，index写两个a标签

```java
@RequestMapping("/user/add")
    public String add(){
        return "user/add";
    }
    @RequestMapping("/user/update")
    public String update(){
        return "user/update";
    }
```

![1588213230372](C:\Users\Mike-laptop\AppData\Roaming\Typora\typora-user-images\1588213230372.png)

修改ShiroConfig.java->getShiroFilterFactoryBean()做测试

```java
//3.shiroFilterFactoryBean
    @Bean
    public ShiroFilterFactoryBean getShiroFilterFactoryBean(@Qualifier("securityManager") DefaultWebSecurityManager defaultWebSecurityManager){
        ShiroFilterFactoryBean bean = new ShiroFilterFactoryBean();
        //设置安全管理器
        bean.setSecurityManager(defaultWebSecurityManager);
        //添加shiro的内置过滤器
        /*
            anon：无需认证就可以访问
            authc:必须认证了才能访问
            user:必须拥有 记住我功能才能用
            perms:拥有对某个资源的权限才能访问
            role：拥有某个角色权限才能访问
         */
        Map<String,String> filterMap = new LinkedHashMap<>();
        filterMap.put("/user/add","authc");
        bean.setFilterChainDefinitionMap(filterMap);
        return bean;
    }
```

此时点击页面发现点add会报错，点update可以正常跳转

我们并不像让他报错，想让他跳转到一个登录页面怎么办呢？

这会新建一个login.html

修改ShiroConfig.java->getShiroFilterFactoryBean(),添加这样一句代码

```java
//设置登陆的请求
bean.setLoginUrl("/toLogin");
```

此时点击权限不够的a标签就会跳转到登录页面

那么我们怎么给一个用户给权限呢？也就是

## 用户认证

### springboot整合shiro,mybatis

1.导包

2.application.yml

3.application.properties

4.pojo

5.mapper->UserMapper(interface)

6.UserMapper.xml

7.UserService

8.UserServiceImpl

9.测试一下，底层能不能成功运行

###  登录请求

```java
 @RequestMapping("/toLogin")
    public String toLogin(){
        return "login";
    }
@RequestMapping("/login")
    public String login(String username,String password,Model model){
        //获取当前用户
        Subject subject = SecurityUtils.getSubject();
        //封装用户的登陆数据
        UsernamePasswordToken token = new UsernamePasswordToken(username, password);
        try{
            subject.login(token);//执行登录方法

            return "index";
        }
        catch(UnknownAccountException e){
            model.addAttribute("msg","用户名错误");
            return "login";
        }catch (IncorrectCredentialsException e){
            model.addAttribute("msg","密码错误");
            return "login";
        }

    }
```

### 认证
#### 连接真实的数据库
