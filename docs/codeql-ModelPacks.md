# CodeQL Model Packs (Model as Data)

```yaml
extensions:
  - addsTo:
      pack: codeql/python-all
      extensible: summaryModel # sourceModel、sinkModel、summaryModel、neutralModel
    data:
      - []

```

- sourceModel(package, type, subtypes, name, signature, ext, output, kind, provenance).
- sinkModel(package, type, subtypes, name, signature, ext, input, kind, provenance).
- summaryModel(package, type, subtypes, name, signature, ext, input, output, kind, provenance)
- neutralModel(package, type, name, signature, kind, provenance)

## sourceModel data

| 索引 | 字段名 | 含义 | 示例值 |
|------|--------|------|--------|
| 0 | package | 包名 (Package Name) | "flask" |
| 1 | type | 类名 (Class Name) (如果是函数则留空或填 "") | "Request" |
| 2 | name | 属性/方法名 (Member Name) | "args" |
| 3 | output | 污点产生的位置 (Access Path) | "Attribute" (属性本身)<br>"ReturnValue" (方法返回值) |
| 4 | kind | 污点类型 (Source Kind) | "remote" (远程输入)<br>"file" (文件读取) |
| 5 | provenance | 来源标记 (通常用于调试) | "manual", "generated" |

## sinkModel data

| 索引 | 字段名 | 含义 | 示例值 |
|------|--------|------|--------|
| 0 | package | 包名 | "sqlite3" |
| 1 | type | 类名 | "Cursor" |
| 2 | name | 方法名 | "execute" |
| 3 | input | 危险参数的位置 (Access Path) | "Argument[0]" (第一个参数) |
| 4 | kind | 漏洞类型 (Sink Kind) | "sql-injection"<br>"command-injection" |
| 5 | provenance | 来源标记 | "manual" |

## summaryModel

| 索引 | 字段名 | 含义 | 示例值 |
|------|--------|------|--------|
| 0 | package | 包名 | "sqlite3" |
| 1 | type | 类名 | "Cursor" |
| 2 | name | 方法名 | "execute" |
| 3 | input | 输入位置 (Source Access Path) | "Argument[0]" (第一个参数) |
| 4 | output | 输出位置 (Target Access Path) | "ReturnValue" |
| 5 | kind | 传播类型 (Flow Kind) | "taint" (污点传播)"value" (值保留) |
| 6 | provenance | 来源标记 | "manual" |


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