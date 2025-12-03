# CodeQL Model Packs (Model as Data)

```yaml
extensions:
  - addsTo:
      pack: codeql/python-all
      extensible: summaryModel # sourceModel、sinkModel、summaryModel、neutralModel
    data:
      - []

```

## Customizing Library Models for Python

- [Customizing Library Models for Python](https://codeql.github.com/docs/codeql-language-guides/customizing-library-models-for-python/)

- sourceModel(type, path, kind)
- sinkModel(type, path, kind)
- typeModel(type1, type2, path)
- summaryModel(type, path, input, output, kind)

### sourceModel

sourceModel(type, path, kind):
- type: Name of a type from which to evaluate path.
- path: Access path leading to the source.
- kind: Kind of source to add. Currently only `remote` is used

#### example

```python
from django.db import models

def user_directory_path(instance, filename): # <-- add 'filename' as a taint source
  # file will be uploaded to MEDIA_ROOT/user_<id>/<filename>
  return "user_{0}/{1}".format(instance.user.id, filename)

class MyModel(models.Model):
  upload = models.FileField(upload_to=user_directory_path) # <-- the 'upload_to' parameter defines our custom function
```

```yaml
extensions:
  - addsTo:
      pack: codeql/python-all
      extensible: sourceModel
    data:
      - [
          "django.db.models.FileField!",
          "Call.Argument[0,upload_to:].Parameter[1]",
          "remote",
        ]
```

- `FileField!`: 类型名称末尾的“ !” 表示我们查找的是类本身，而不是该类的实例
- `[0,upload_to:]`: 选择第一个位置参数，或者名为 upload_to 的命名参数。请注意，参数名称末尾的冒号表示我们正在查找命名参数

### sinkModel

sinkModel(type, path, kind):
- type: Name of a type from which to evaluate path.
- path: Access path leading to the sink.
- kind: Kind of sink to add. See the section on sink kinds for a list of supported kinds.

Kind of sink:
- code-injection: A sink that can be used to inject code, such as in calls to exec.
- command-injection: A sink that can be used to inject shell commands, such as in calls to os.system.
- path-injection: A sink that can be used for path injection in a file system access, such as in calls to flask.send_from_directory.
- sql-injection: A sink that can be used for SQL injection, such as in a MySQL query call.
- html-injection: A sink that can be used for HTML injection, such as a server response body.
- js-injection: A sink that can be used for JS injection, such as a server response body.
- url-redirection: A sink that can be used to redirect the user to a malicious URL.
- unsafe-deserialization: A deserialization sink that can lead to code execution or other unsafe behavior, such as an unsafe YAML parser.
- log-injection: A sink that can be used for log injection, such as in a logging.info call.

#### example

```python
import invoke
c = invoke.Context()
c.run(cmd) # <-- add 'cmd' as a taint sink
```

```
extensions:
  - addsTo:
      pack: codeql/python-all
      extensible: sinkModel
    data:
      - ["invoke", "Member[Context].Instance.Member[run].Argument[0]", "command-injection"]
```

### summaryModel

summaryModel(type, path, input, output, kind):
- type: Name of a type from which to evaluate path.
- path: Access path leading to a function call.
- input: Path relative to the function call that leads to input of the flow.
- output: Path relative to the function call leading to the output of the flow.
- kind: Kind of summary to add. Can be `taint` for taint-propagating flow, or `value for` value-preserving flow.

#### example 

```yaml
extensions:
  - addsTo:
      pack: codeql/python-all
      extensible: summaryModel
    data:
      - [
          "builtins",
          "Member[reversed]",
          "Argument[0]",
          "ReturnValue",
          "taint",
        ]
```

### typeModel

- type1: Name of the type to reach.
- type2: Name of the type from which to evaluate path.
- path: Access path leading from type2 to type1.

#### example 

```yaml
extensions:
- addsTo:
    pack: codeql/python-all
    extensible: typeModel
  data:
    - [
        "flask.Response",
        "flask",
        "Member[jsonify].ReturnValue",
      ]
```

## types

类型是一个字符串，用于标识一组值。在上一节提到的每个可扩展谓词中，第一列始终是类型名称。可以通过添加该类型的 typeModel 元组来定义类型。此外，还提供以下内置类型：

- 包的名称与该包的导入语句相匹配。例如，类型 django 与表达式 import django 相匹配。
- 类型 builtins 用于标识 builtins 包。在 Python 中，所有内置函数值都位于此包中，因此可以使用此类型来标识它们。
- 以类名结尾的点路径标识该类的实例。如果添加后缀“ !” ，则类型指向类本身。

## Access paths

路径 、 输入和输出列由以句点分隔的组件列表组成，从左到右进行评估，每一步都从前一组值中选择一组新的值

- Argument[number] selects the argument at the given index.
- Argument[name:] selects the argument with the given name.
- Argument[this] selects the receiver of a method call.
- Parameter[number] selects the parameter at the given index.
- Parameter[name:] selects the named parameter with the given name.
- Parameter[this] selects the this parameter of a function.
- ReturnValue selects the return value of a function or call.
- Member[name] selects the function/method/class/value with the given name.
- Instance selects instances of a class, including instances of its subclasses.
- Attribute[name] selects the attribute with the given name.
- ListElement selects an element of a list.
- SetElement selects an element of a set.
- TupleElement[number] selects the subscript at the given index.
- DictionaryElement[name] selects the subscript at the given name.

Additional notes about the syntax of operands:

- Multiple operands may be given to a single component, as a shorthand for the union of the operands. For example, Member[foo,bar] matches the union of Member[foo] and Member[bar].
- Numeric operands to Argument, Parameter, and WithArity may be given as an interval. For example, Argument[0..2] matches argument 0, 1, or 2.
- Argument[N-1] selects the last argument of a call, and Parameter[N-1] selects the last parameter of a function, with N-2 being the second-to-last and so on.


## Summary kinds
taint: A summary that propagates taint. This means the output is not necessarily equal to the input, but it was derived from the input in an unrestrictive way. An attacker who controls the input will have significant control over the output as well.

value: A summary that preserves the value of the input or creates a copy of the input such that all of its object properties are preserved.


## 不足

### 无法表达“条件流向” (Conditional Flow)
这是 YAML 最大的短板。它只能定义“如果是 A，那就是 B”，无法定义“只有在 C 发生时，A 才是 B”。

YAML 做不到的场景：

`“如果参数 verify=False，那么 fetch_url 才是 Sink；如果 verify=True，它是安全的。”`

QL 代码的优势：

```ql
// .qll 可以轻松写出条件逻辑
override predicate isSink(DataFlow::Node sink) {
  exists(CallNode call |
    call.getFunction().getName() == "fetch_url" and
    sink = call.getArgument(0) and
    // 检查 verify 参数是否为 False
    call.getArgByName("verify").(BooleanLiteral).getValue() == false 
  )
}
```

影响：用 YAML 建模可能会导致误报（因为忽略了安全配置参数）。

### “净化器”表达能力不足 (Sanitizers / Guards)

不足一：无法区分“针对性净化”
在 QL 代码中，我们可以非常精细地定义：

“这个函数只能净化 XSS 污点，但不能净化 SQL注入 污点。”

但在 YAML 的 neutral 模型中，它通常是一刀切的。如果你把它标记为 neutral，数据流就在这里断了。无论原本跟踪的是 SQL 注入还是 XSS，流到这里都断了（除非 CodeQL 的底层实现支持在 neutral 中细分 tag，但目前 Model Packs 的主流用法主要处理通用数据流）。

不足二：无法支持“Guard”（守卫/校验）
这是 YAML 格式最大的痛点。

CodeQL (QL) 能力：可以识别 if 条件。

例如：if (isValid(x)) { use(x); }。QL 可以识别出在 if 块内部，x 是被净化过的。

YAML 能力：完全做不到。

YAML 只能描述函数调用（Call Site）的输入输出关系。它无法描述“如果代码里写了一个 if 语句，那么...”这样的控制流逻辑。

所以，YAML 只能定义 Sanitizer Function（净化函数，如 escape()），无法定义 Sanitizer Guard（校验逻辑，如 isValid()）。

### 匹配粒度较粗 (Name-based Matching)

YAML 的匹配完全依赖于字符串（包名、类名、函数名）。

YAML 的局限：

它很难处理动态生成的代码或复杂的继承结构，除非你把所有子类名都列出来。

它无法像 QL 那样通过 AST 结构去模糊匹配（例如：“所有包含 execute 且参数名为 sql 的方法”）。

QL 代码的优势：

QL 可以利用 AST 特征进行强大的启发式匹配，不依赖具体的函数名。

### 上下文缺失 (Context Insensitivity)

YAML 定义的 Summary Model 通常是上下文无关的。

场景：

container.get(key)。
如果 container 存的是敏感数据，取出来就是敏感的；如果是普通数据，取出来就是普通的。

YAML 的处理：

通常只能粗暴地定义：Argument[0] (self) -> ReturnValue。即：只要容器脏，取出来都脏。这在大多数情况下没问题，但在复杂场景下可能导致污点爆炸（Over-tainting）。

### 依赖版本问题 

第三方库是会更新的。

如果 MyLibrary v1.0 的 funcA 是不安全的，但 v2.0 修复了。

如何写model pack？