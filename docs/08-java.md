# Java 场景应用

> Java/Kotlin 企业级应用安全分析完整指南，涵盖 Spring、JPA、微服务等主流技术栈

## Java 语言支持概览

### 目录结构

```
java/
├── ql/
│   ├── lib/                    # Java 核心库
│   │   ├── semmle/code/java/  # 标准库实现
│   │   │   ├── dataflow/      # 数据流分析
│   │   │   ├── security/      # 安全相关
│   │   │   ├── frameworks/    # 框架支持
│   │   │   │   ├── spring/    # Spring Framework
│   │   │   │   ├── javaee/    # Java EE
│   │   │   │   ├── android/   # Android 开发
│   │   │   │   └── apache/    # Apache 组件
│   │   │   └── Concepts.qll   # 通用概念
│   │   ├── qlpack.yml         # 库包配置
│   │   └── java.qll           # 主入口文件
│   ├── src/                    # 查询源码
│   │   ├── Security/CWE/      # 安全查询（按 CWE 分类）
│   │   │   ├── CWE-089/      # SQL 注入
│   │   │   ├── CWE-078/      # 命令注入
│   │   │   ├── CWE-079/      # XSS
│   │   │   └── CWE-502/      # 反序列化
│   │   ├── Performance/       # 性能相关查询
│   │   ├── Likely Bugs/       # 可能的 Bug
│   │   └── codeql-suites/     # 预定义查询套件
│   ├── test/                   # 测试用例
│   └── examples/               # 示例查询
├── kotlin-extractor/           # Kotlin 支持
└── automodel/                  # 自动模型生成
```

### 支持的 Java 版本

- **Java 8** - 完全支持
- **Java 11** - 完全支持  
- **Java 17** - 完全支持
- **Java 21** - 完全支持
- **Kotlin** - 1.3+ 支持

### 框架支持

| 框架类型 | 支持的框架 | 位置 |
|----------|------------|------|
| **Web 框架** | Spring MVC, Spring Boot, JAX-RS | `semmle/code/java/frameworks/spring/` |
| **ORM 框架** | Hibernate, JPA, MyBatis | `semmle/code/java/frameworks/jpa/` |
| **依赖注入** | Spring IoC, CDI, Guice | `semmle/code/java/frameworks/spring/` |
| **安全框架** | Spring Security, Shiro | `semmle/code/java/security/` |
| **消息队列** | JMS, RabbitMQ, Kafka | `semmle/code/java/frameworks/` |
| **Android** | Android SDK, Support Library | `semmle/code/java/frameworks/android/` |

## Java 核心类和概念

### 基本语法元素

```ql
import java

// 类
from Class c
select c.getName(), c.getQualifiedName(), c.getPackage()

// 方法
from Method m
select m.getName(), m.getDeclaringType(), m.getSignature()

// 字段
from Field f
select f.getName(), f.getType(), f.getDeclaringType()

// 方法调用
from MethodCall call
select call.getMethod(), call.getQualifier(), call.getArgument(0)

// 构造函数调用
from ConstructorCall call
select call.getConstructor(), call.getArgument(0)

// 注解
from Annotation ann
select ann.getType(), ann.getValue("value")
```

### Java 特定类

```ql
import java

// 接口
from Interface i
select i.getName(), i.getASubtype()

// 枚举
from EnumType e
select e.getName(), e.getAnEnumConstant()

// 泛型
from ParameterizedType pt
select pt.getGenericType(), pt.getTypeArgument(0)

// 异常处理
from TryStmt try, CatchClause catch
where catch = try.getACatchClause()
select try, catch.getVariable().getType()

// Lambda 表达式
from LambdaExpr lambda
select lambda.getExprBody(), lambda.getAParameter()

// 流式 API
from MethodCall call
where call.getMethod().hasName("stream")
select call, call.getQualifier()
```

## Spring Framework 安全分析

### 1. Spring MVC 路由分析

```ql
/**
 * @name Spring MVC 路由分析
 * @description 分析 Spring MVC 控制器的路由映射
 * @kind problem
 * @id java/spring-mvc-route-analysis
 */

import java
import semmle.code.java.frameworks.spring.SpringController

from SpringController controller, SpringControllerMethod method
where method.getDeclaringType() = controller
select method, 
  "Spring 路由: " + method.getRequestMappingUrl() + 
  " [" + method.getRequestMappingMethod() + "]"
```

### 2. Spring SQL 注入检测

```ql
/**
 * @name Spring SQL 注入检测
 * @description 检测 Spring 应用中的 SQL 注入漏洞
 * @kind path-problem
 * @problem.severity error
 * @security-severity 8.8
 * @precision high
 * @id java/spring-sql-injection
 * @tags security
 *       external/cwe/cwe-089
 *       external/owasp/owasp-a03
 */

import java
import semmle.code.java.dataflow.TaintTracking
import semmle.code.java.security.SqlInjectionQuery
import semmle.code.java.frameworks.spring.SpringController
import QueryInjectionFlow::PathGraph

class SpringSqlInjectionConfig extends TaintTracking::Configuration {
  SpringSqlInjectionConfig() { this = "SpringSqlInjectionConfig" }

  override predicate isSource(DataFlow::Node source) {
    // Spring 控制器参数
    exists(SpringControllerMethod method, Parameter param |
      param = method.getAParameter() and
      source.asParameter() = param and
      // 排除基本类型的路径变量（相对安全）
      not (param.getAnAnnotation().getType().hasName("PathVariable") and
           param.getType() instanceof PrimitiveType)
    )
  }

  override predicate isSink(DataFlow::Node sink) {
    // JDBC 执行方法
    exists(MethodCall call |
      call.getMethod().hasName("execute") and
      call.getMethod().getDeclaringType().hasQualifiedName("java.sql", "Statement") and
      sink.asExpr() = call.getArgument(0)
    )
    or
    // JPA 原生查询
    exists(MethodCall call |
      call.getMethod().hasName("createNativeQuery") and
      sink.asExpr() = call.getArgument(0)
    )
    or
    // MyBatis 动态 SQL
    exists(MethodCall call |
      call.getMethod().getDeclaringType().getPackage().getName().matches("org.apache.ibatis%") and
      call.getMethod().hasName("selectList") and
      sink.asExpr() = call.getArgument(0)
    )
  }

  override predicate isSanitizer(DataFlow::Node node) {
    // 参数化查询
    exists(MethodCall call |
      call.getMethod().hasName("prepareStatement") and
      node.asExpr() = call.getArgument(0)
    )
    or
    // Spring 的转义方法
    exists(MethodCall call |
      call.getMethod().hasName("escape") and
      call.getMethod().getDeclaringType().getPackage().getName().matches("org.springframework%") and
      node.asExpr() = call
    )
  }

  override predicate isAdditionalTaintStep(DataFlow::Node fromNode, DataFlow::Node toNode) {
    // 字符串拼接
    exists(AddExpr add |
      (fromNode.asExpr() = add.getLeftOperand() or fromNode.asExpr() = add.getRightOperand()) and
      toNode.asExpr() = add
    )
    or
    // StringBuilder 操作
    exists(MethodCall call |
      call.getMethod().hasName("append") and
      call.getMethod().getDeclaringType().hasName("StringBuilder") and
      fromNode.asExpr() = call.getArgument(0) and
      toNode.asExpr() = call
    )
  }
}

from SpringSqlInjectionConfig config, DataFlow::PathNode source, DataFlow::PathNode sink
where config.hasFlowPath(source, sink)
select sink.getNode(), source, sink, 
  "Spring SQL 查询包含用户输入 $@，可能导致 SQL 注入", 
  source.getNode(), "控制器参数"
```

### 3. Spring Security 配置检查

```ql
/**
 * @name Spring Security 不安全配置
 * @description 检测 Spring Security 的不安全配置
 * @kind problem
 * @problem.severity error
 * @security-severity 7.5
 * @id java/spring-security-insecure-config
 * @tags security
 *       external/cwe/cwe-284
 *       external/owasp/owasp-a01
 */

import java

from MethodCall call, Method method
where
  // Spring Security 配置方法
  method = call.getMethod() and
  (
    // 禁用 CSRF 保护
    (method.hasName("disable") and
     call.getQualifier().(MethodCall).getMethod().hasName("csrf")) or
    
    // 允许所有请求
    (method.hasName("permitAll") and
     call.getQualifier().(MethodCall).getMethod().hasName("anyRequest")) or
     
    // 禁用框架点击劫持保护
    (method.hasName("disable") and
     call.getQualifier().(MethodCall).getMethod().hasName("frameOptions")) or
     
    // 使用不安全的密码编码器
    (method.hasName("passwordEncoder") and
     exists(ConstructorCall cons |
       cons = call.getArgument(0) and
       cons.getConstructor().getDeclaringType().hasName("NoOpPasswordEncoder")
     ))
  )

select call, "Spring Security 不安全配置: " + method.getName()
```

### 4. Spring Boot Actuator 暴露检查

```ql
/**
 * @name Spring Boot Actuator 端点暴露
 * @description 检测可能暴露敏感信息的 Actuator 端点
 * @kind problem
 * @problem.severity warning
 * @security-severity 6.5
 * @id java/spring-boot-actuator-exposure
 * @tags security
 *       external/cwe/cwe-200
 */

import java

from Field field, FieldAccess access
where
  // application.properties 或 application.yml 中的配置
  field.getName().matches("management.endpoints.web.exposure.include") and
  access.getField() = field and
  (
    // 暴露所有端点
    access.toString().matches("*") or
    // 暴露敏感端点
    access.toString().regexpMatch(".*(env|configprops|mappings|beans|health|info|metrics).*")
  )

select access, "Spring Boot Actuator 暴露了敏感端点: " + access.toString()
```

## JPA/Hibernate 安全分析

### 1. JPA 查询注入检测

```ql
/**
 * @name JPA 查询注入检测
 * @description 检测 JPA/JPQL 查询中的注入漏洞
 * @kind path-problem
 * @problem.severity error
 * @security-severity 8.5
 * @id java/jpa-query-injection
 * @tags security
 *       external/cwe/cwe-089
 */

import java
import semmle.code.java.dataflow.TaintTracking
import DataFlow::PathGraph

class JpaQueryInjectionConfig extends TaintTracking::Configuration {
  JpaQueryInjectionConfig() { this = "JpaQueryInjectionConfig" }

  override predicate isSource(DataFlow::Node source) {
    // HTTP 请求参数
    exists(Parameter param |
      param.getAnAnnotation().getType().hasName("RequestParam") and
      source.asParameter() = param
    )
    or
    // 路径变量
    exists(Parameter param |
      param.getAnAnnotation().getType().hasName("PathVariable") and
      param.getType() instanceof RefType and  // 非基本类型
      source.asParameter() = param
    )
  }

  override predicate isSink(DataFlow::Node sink) {
    // JPA 查询创建
    exists(MethodCall call |
      call.getMethod().hasName("createQuery") and
      call.getMethod().getDeclaringType().hasQualifiedName("javax.persistence", "EntityManager") and
      sink.asExpr() = call.getArgument(0)
    )
    or
    // Hibernate 查询
    exists(MethodCall call |
      call.getMethod().hasName("createQuery") and
      call.getMethod().getDeclaringType().getPackage().getName().matches("org.hibernate%") and
      sink.asExpr() = call.getArgument(0)
    )
  }

  override predicate isSanitizer(DataFlow::Node node) {
    // 使用参数化查询
    exists(MethodCall call |
      call.getMethod().hasName("setParameter") and
      node.asExpr() = call.getQualifier()
    )
  }
}

from JpaQueryInjectionConfig config, DataFlow::PathNode source, DataFlow::PathNode sink
where config.hasFlowPath(source, sink)
select sink.getNode(), source, sink, 
  "JPA 查询包含用户输入 $@，应使用参数化查询", 
  source.getNode(), "请求参数"
```

### 2. Hibernate 二级缓存配置检查

```ql
/**
 * @name Hibernate 不安全的缓存配置
 * @description 检测可能导致数据泄露的 Hibernate 缓存配置
 * @kind problem
 * @problem.severity warning
 * @id java/hibernate-insecure-cache-config
 */

import java

from Annotation ann, AnnotationElement elem
where
  ann.getType().hasName("Cache") and
  elem = ann.getValue("usage") and
  elem.toString().matches("*READ_WRITE*") and
  // 实体包含敏感信息
  exists(Field field |
    field.getDeclaringType() = ann.getAnnotatedElement() and
    field.getName().regexpMatch("(?i).*(password|secret|token|key|ssn|credit).*")
  )

select ann, "敏感实体使用了 READ_WRITE 缓存策略，可能导致数据泄露"
```

## Android 安全分析

### 1. Android 权限检查

```ql
/**
 * @name Android 危险权限使用
 * @description 检测 Android 应用使用的危险权限
 * @kind problem
 * @problem.severity warning
 * @id java/android-dangerous-permissions
 * @tags security
 *       mobile
 *       external/cwe/cwe-250
 */

import java
import semmle.code.java.frameworks.android.Android

from AndroidManifestXmlFile manifest, AndroidPermission perm
where
  perm.isDangerous() and
  manifest.declaresPermission(perm)

select manifest, "Android 应用声明了危险权限: " + perm.getName()
```

### 2. Android Intent 安全检查

```ql
/**
 * @name Android 不安全的 Intent 使用
 * @description 检测可能导致 Intent 劫持的不安全 Intent 使用
 * @kind path-problem
 * @problem.severity error
 * @security-severity 7.5
 * @id java/android-unsafe-intent
 * @tags security
 *       mobile
 *       external/cwe/cwe-926
 */

import java
import semmle.code.java.dataflow.TaintTracking
import semmle.code.java.frameworks.android.Intent
import DataFlow::PathGraph

class UnsafeIntentConfig extends TaintTracking::Configuration {
  UnsafeIntentConfig() { this = "UnsafeIntentConfig" }

  override predicate isSource(DataFlow::Node source) {
    // Intent 额外数据
    exists(MethodCall call |
      call.getMethod().hasName("getStringExtra") and
      source.asExpr() = call
    )
  }

  override predicate isSink(DataFlow::Node sink) {
    // 启动 Activity
    exists(MethodCall call |
      call.getMethod().hasName("startActivity") and
      sink.asExpr() = call.getArgument(0)
    )
    or
    // 发送广播
    exists(MethodCall call |
      call.getMethod().hasName("sendBroadcast") and
      sink.asExpr() = call.getArgument(0)
    )
  }
}

from UnsafeIntentConfig config, DataFlow::PathNode source, DataFlow::PathNode sink
where config.hasFlowPath(source, sink)
select sink.getNode(), source, sink, 
  "不安全的 Intent 使用，数据来源于 $@", 
  source.getNode(), "Intent 额外数据"
```

## 企业级安全模式

### 1. 微服务间通信安全

```ql
/**
 * @name 微服务间不安全通信
 * @description 检测微服务间缺少认证的 HTTP 调用
 * @kind problem
 * @problem.severity error
 * @security-severity 7.0
 * @id java/microservice-insecure-communication
 * @tags security
 *       microservices
 *       external/cwe/cwe-306
 */

import java

predicate isServiceCall(MethodCall call) {
  // RestTemplate 调用
  call.getMethod().getDeclaringType().hasName("RestTemplate") and
  call.getMethod().hasName("exchange") or
  
  // Feign 客户端调用
  call.getMethod().getDeclaringType().getAnAnnotation().getType().hasName("FeignClient") or
  
  // WebClient 调用
  call.getMethod().getDeclaringType().hasName("WebClient")
}

predicate hasAuthentication(MethodCall call) {
  // 检查是否有认证头
  exists(MethodCall headerCall |
    headerCall.getMethod().hasName("header") and
    headerCall.getArgument(0).(StringLiteral).getValue() = "Authorization" and
    headerCall.getQualifier*() = call.getQualifier()
  ) or
  
  // 检查是否使用了认证拦截器
  exists(MethodCall interceptorCall |
    interceptorCall.getMethod().hasName("setInterceptors") and
    interceptorCall.getQualifier() = call.getQualifier()
  )
}

from MethodCall call
where 
  isServiceCall(call) and
  not hasAuthentication(call) and
  // 排除本地调用
  not call.getArgument(0).(StringLiteral).getValue().matches("http://localhost*")

select call, "微服务调用缺少身份认证"
```

### 2. JWT Token 安全检查

```ql
/**
 * @name JWT Token 不安全使用
 * @description 检测 JWT Token 的不安全实现
 * @kind problem
 * @problem.severity error
 * @security-severity 8.0
 * @id java/jwt-insecure-usage
 * @tags security
 *       jwt
 *       external/cwe/cwe-347
 */

import java

from MethodCall call, Method method
where
  method = call.getMethod() and
  method.getDeclaringType().getPackage().getName().matches("io.jsonwebtoken%") and
  (
    // 使用 none 算法
    (method.hasName("signWith") and
     call.getArgument(0).(FieldAccess).getField().hasName("NONE")) or
    
    // 不验证签名
    (method.hasName("parseClaimsJwt") and
     not exists(MethodCall verifyCall |
       verifyCall.getMethod().hasName("setSigningKey") and
       verifyCall.getQualifier() = call.getQualifier()
     )) or
     
    // 使用弱密钥
    (method.hasName("setSigningKey") and
     exists(StringLiteral key |
       key = call.getArgument(0) and
       key.getValue().length() < 32
     ))
  )

select call, "JWT Token 不安全使用: " + method.getName()
```

### 3. 配置文件敏感信息检查

```ql
/**
 * @name 配置文件敏感信息泄露
 * @description 检测配置文件中的硬编码敏感信息
 * @kind problem
 * @problem.severity error
 * @security-severity 8.5
 * @id java/config-sensitive-info-exposure
 * @tags security
 *       external/cwe/cwe-798
 */

import java

from StringLiteral str, string value
where
  value = str.getValue() and
  (
    // 数据库密码
    (str.getParentNode*().(AssignExpr).getDestination().toString().matches("*password*") and
     value.length() > 5 and
     not value.matches("${*}") and  // 排除占位符
     not value.regexpMatch("(?i).*(example|test|dummy).*")) or
    
    // API 密钥
    (str.getParentNode*().(AssignExpr).getDestination().toString().regexpMatch("(?i).*(api.?key|secret|token).*") and
     value.length() > 10 and
     not value.matches("${*}")) or
     
    // 加密密钥
    (value.regexpMatch("[A-Za-z0-9+/]{32,}={0,2}") and  // Base64 编码的密钥
     str.getParentNode*().(AssignExpr).getDestination().toString().regexpMatch("(?i).*(key|secret).*"))
  )

select str, "配置文件包含硬编码的敏感信息: " + value.prefix(20) + "..."
```

## 性能和资源管理

### 1. 资源泄露检查

```ql
/**
 * @name Java 资源泄露
 * @description 检测未正确关闭的资源，可能导致内存泄露
 * @kind problem
 * @problem.severity warning
 * @id java/resource-leak
 * @tags reliability
 *       performance
 */

import java

predicate isResource(Type t) {
  t.getASourceSupertype*().hasQualifiedName("java.io", "Closeable") or
  t.getASourceSupertype*().hasQualifiedName("java.lang", "AutoCloseable")
}

predicate isProperlyManaged(Variable v) {
  // try-with-resources
  exists(TryStmt try |
    try.getAResourceVariable() = v
  ) or
  
  // 显式关闭
  exists(MethodCall close |
    close.getMethod().hasName("close") and
    close.getQualifier() = v.getAnAccess()
  ) or
  
  // 在 finally 块中关闭
  exists(TryStmt try, MethodCall close |
    close.getMethod().hasName("close") and
    close.getQualifier() = v.getAnAccess() and
    close.getParent+() = try.getFinally()
  )
}

from LocalVariableDecl decl, Variable v
where
  v = decl.getAVariable() and
  isResource(v.getType()) and
  not isProperlyManaged(v) and
  // 排除测试代码
  not decl.getCompilationUnit().getRelativePath().matches("*test*")

select decl, "资源 '" + v.getName() + "' 可能未正确关闭，建议使用 try-with-resources"
```

### 2. 大对象创建检查

```ql
/**
 * @name 循环中的大对象创建
 * @description 检测在循环中创建大对象的性能问题
 * @kind problem
 * @problem.severity warning
 * @id java/large-object-in-loop
 * @tags performance
 */

import java

predicate isLargeObject(Type t) {
  t.hasQualifiedName("java.util", "ArrayList") or
  t.hasQualifiedName("java.util", "HashMap") or
  t.hasQualifiedName("java.lang", "StringBuilder") or
  t.hasQualifiedName("java.lang", "StringBuffer") or
  t.hasName("BigDecimal") or
  t.hasName("BigInteger")
}

from LoopStmt loop, ConstructorCall cons
where
  cons.getParent+() = loop and
  isLargeObject(cons.getConstructedType()) and
  // 不是集合的初始化
  not exists(MethodCall add |
    add.getMethod().hasName("add") and
    add.getQualifier() = cons.getParent()
  )

select cons, "在循环中创建大对象 '" + cons.getConstructedType().getName() + 
  "'，考虑移到循环外部或使用对象池"
```

## 代码质量检查

### 1. 空指针异常风险

```ql
/**
 * @name 潜在的空指针异常
 * @description 检测可能导致 NullPointerException 的代码
 * @kind problem
 * @problem.severity error
 * @id java/potential-null-pointer-exception
 * @tags reliability
 *       external/cwe/cwe-476
 */

import java
import semmle.code.java.dataflow.NullGuards

from MethodCall call, Expr qualifier
where
  qualifier = call.getQualifier() and
  // 可能为 null 的表达式
  (
    // 方法返回值可能为 null
    exists(Method m |
      m = qualifier.(MethodCall).getMethod() and
      (m.hasName("get") or m.hasName("find") or m.hasName("search")) and
      not m.getReturnType() instanceof PrimitiveType
    ) or
    
    // 字段可能为 null
    qualifier instanceof FieldAccess or
    
    // 数组访问可能为 null
    qualifier instanceof ArrayAccess
  ) and
  
  // 没有空值检查
  not nullGuarded(qualifier) and
  
  // 排除已知非空的情况
  not qualifier.getType() instanceof PrimitiveType

select call, "方法调用的限定符可能为 null，建议添加空值检查"
```

### 2. 线程安全问题

```ql
/**
 * @name 线程安全问题
 * @description 检测可能的线程安全问题
 * @kind problem
 * @problem.severity warning
 * @id java/thread-safety-issue
 * @tags concurrency
 *       external/cwe/cwe-362
 */

import java

predicate isThreadUnsafe(Type t) {
  t.hasQualifiedName("java.util", "ArrayList") or
  t.hasQualifiedName("java.util", "HashMap") or
  t.hasQualifiedName("java.util", "HashSet") or
  t.hasQualifiedName("java.lang", "StringBuilder") or
  t.hasQualifiedName("java.text", "SimpleDateFormat")
}

from Field field
where
  isThreadUnsafe(field.getType()) and
  not field.isPrivate() and
  not field.isFinal() and
  not field.hasAnnotation("ThreadSafe") and
  // 在多线程环境中使用
  exists(Method m |
    m.getDeclaringType() = field.getDeclaringType() and
    (m.hasAnnotation("Async") or 
     m.getDeclaringType().hasAnnotation("Service") or
     m.getDeclaringType().hasAnnotation("Controller"))
  )

select field, "字段 '" + field.getName() + "' 使用了线程不安全的类型 '" + 
  field.getType().getName() + "'，在多线程环境中可能出现问题"
```

## 测试和示例

### 创建测试用例

**测试目录结构：**
```
test/
├── Security/
│   └── CWE/
│       └── CWE-089/
│           └── SqlTainted/
│               ├── Test.java
│               ├── SqlTainted.qlref
│               └── SqlTainted.expected
```

**Test.java:**
```java
import javax.servlet.http.HttpServletRequest;
import java.sql.Connection;
import java.sql.Statement;
import java.sql.PreparedStatement;

public class Test {
    public void bad(HttpServletRequest request, Connection conn) throws Exception {
        // 应该被检测到的 SQL 注入
        String userId = request.getParameter("id");
        String query = "SELECT * FROM users WHERE id = '" + userId + "'";
        Statement stmt = conn.createStatement();
        stmt.execute(query);
    }
    
    public void good(HttpServletRequest request, Connection conn) throws Exception {
        // 不应该被检测到（参数化查询）
        String userId = request.getParameter("id");
        String query = "SELECT * FROM users WHERE id = ?";
        PreparedStatement stmt = conn.prepareStatement(query);
        stmt.setString(1, userId);
        stmt.execute();
    }
}
```

### 运行 Java 查询

```bash
# 在您的 Java 项目目录中
cd ~/codeql-projects/my-projects/your-java-project

# 创建 Java 数据库
codeql database create java-db --language=java --source-root=.

# 运行单个查询（使用 CodeQL 标准库中的查询）
codeql query run ~/codeql-projects/codeql/java/ql/src/Security/CWE/CWE-089/SqlTainted.ql \
  --database=java-db

# 运行 Java 安全套件
codeql database analyze java-db \
  ~/codeql-projects/codeql/java/ql/src/codeql-suites/java-security-and-quality.qls \
  --format=sarif-latest --output=results.sarif
```

## 最佳实践

### 1. 利用 Java 特定的 API

```ql
import java
import semmle.code.java.frameworks.spring.SpringController

// 使用 Spring 特定的类
from SpringController controller
select controller, controller.getARequestMappingMethod()

// 使用 JPA 特定的类
from JpaEntity entity
select entity, entity.getAnEntityAnnotation()
```

### 2. 处理 Java 的类型系统

```ql
// 处理泛型
from ParameterizedType pt
where pt.getGenericType().hasName("List")
select pt, pt.getTypeArgument(0)

// 处理继承关系
from Method m
where m.overrides(_)
select m, "重写方法"

// 处理注解
from Annotatable element, Annotation ann
where ann = element.getAnAnnotation()
select element, ann.getType().getName()
```

### 3. 框架特定的优化

```ql
// 专门针对 Spring Boot 的查询
import semmle.code.java.frameworks.spring.SpringBoot

from SpringBootApplication app
select app, "Spring Boot 应用"

// 针对 Android 的查询
import semmle.code.java.frameworks.android.Android

from AndroidActivity activity
select activity, "Android Activity"
```

## 下一步

掌握了 Java 场景应用后，建议继续学习：

1. **[JavaScript 场景](09-javascript.md)** - 前端和 Node.js 安全分析
2. **[其他语言](10-other-languages.md)** - Go、C/C++、C# 等语言支持
3. **[最佳实践](12-best-practices.md)** - 查询优化和调试技巧

---

**Java 场景掌握完毕！** ☕ 现在您可以分析各种 Java 企业级应用的安全问题了。
