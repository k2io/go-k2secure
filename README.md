# K2 Cyber Security Go Collector

GoLang language collector is integrated during the build process.
## Compatibility

- **Go version:** `1.15 and above`
- **Architectures:** `amd64`
- **Operating systems:**  `linux` 
- **Frameworks:**  `net/http` `fasthttp` `gRPC` 
## Stable Releases

#### Get latest release for go-agent


| Tag | Release Date     | Release Notes                |
| :-------- | :------- | :------------------------- |
| `v2.0.0` | `2022-02-15` | [Release Notes](https://github.com/k2io/go-k2secure/releases/tag/2.0.0) |


## Installation
**Note**: go-k2secure agent is supposed to be used with other K2 services and not individually. For this, an account is needed on [k2io.net](http://k2io.net/) where further instructions can be found.

**Step 1**: The K2-Go agent can be attached to your application by running the following commands:

- Use the standard golang method to get the K2 package

```bash
go get github.com/k2io/go-k2secure@v2.0.0
```
**Step 2**: Import the K2 package into the main module of the application.
```bash
import _ "github.com/k2io/go-k2secure"                      
```
**Note**: Import the K2 package before other packages. This ensures it is initialized before any GRPC service registration from any package initialization code.

**Step 3**: Based on additional packages imported by the user application, add suitable imports. 


| Package used | K2 Instrumentation package (additionally import)| 
| :-------- | :------- |
|`google.golang.org/grpc` | `import _ "http://github.com/k2io/go-k2secure/k2secure/k2secure_grpcwrap"`|
|`github.com/valyala/fasthttp`|`import _ "http://github.com/k2io/go-k2secure/k2secure/k2secure_fasthttpwrap"`|
|`github.com/antchfx/xpath`|`import _ "http://github.com/k2io/go-k2secure/k2secure/k2secure_xpathwrap"`|
|`github.com/antchfx/xmlquery`|`import _ "http://github.com/k2io/go-k2secure/k2secure/k2secure_xmlquerywrap"`|
|`github.com/antchfx/jsonquery`|`import _ "http://github.com/k2io/go-k2secure/k2secure/k2secure_jsonquerywrap"`|
|`github.com/antchfx/htmlquery`|`import _ "http://github.com/k2io/go-k2secure/k2secure/k2secure_htmlquerywrap"`|
|`go.mongodb.org/mongo-driver/mongo`|`import _ "http://github.com/k2io/go-k2secure/k2secure/k2secure_mongowrap"`|
|`github.com/robertkrimen/otto`|`import _ "http://github.com/k2io/go-k2secure/k2secure/k2secure_ottowrap"`|
|`github.com/augustoroman/v8`|`import _ "http://github.com/k2io/go-k2secure/k2secure/k2secure_v8wrap"`|
|`github.com/go-ldap/ldap/v3`|`import _ "http://github.com/k2io/go-k2secure/k2secure/k2secure_ldapwrap"`|

Note: If the latest version of K2 package is NOT being used, it is required to get the corresponding version of K2 Instrumentation packages because by default latest version of K2 Instrumentation packages are imported. This can be done like the following example.

Example:
If following import is used:
```
import _ "github.com/k2io/go-k2secure/k2secure/k2secure_grpcwrap/v2"
```
Perform the following step:
```
go get github.com/k2io/go-k2secure/k2secure/k2secure_grpcwrap/v2@2.0.0-rc7
```

**Step 4**: Special Instructions when the application is running in IAST mode with gRPC

**Note**: If the running application in IAST mode with gRPC, follow the special instructions given below otherwise skip to Step 5.

Create the file  k2GrpcConf.json  in the directory where the application binary is running from in the following format.
```
{
 "importPaths": [
  "<directory_of_protofile>",
  "<directory_of_protofile>"
 ],
 "importedFiles": [
  "<ProtoFile1>.proto",
  "<ProtoFile2>.proto",
  "<ProtoFil3>.proto"
 ]
}
```
importPaths : All the paths where proto files used by the application are placed (can be multiple entries)

importedFiles: All the proto files used by the application (can be multiple entries)

**Note**: If the k2GrpcConf.json  is not created, K2 golang agent would create k2GrpcConf.json in the directory where the application binary is running from. 

**Step 5**:  Build and Run the Application using the following build process 

```bash
go build  -gcflags "-l" main.go
./main
```

**Note**: Inlining is disabled to allow K2 to intercept key methods.

To verify if the given application is protected by K2 Prevent-Web, refer to the "Protected processes" subsection of the "Applications" page and locate the application based on name and node IP. The host namespace PID(in case of a host application) and container namespace PID(in case of a containerised application) can also be used to locate the protected application.


## Example



```bash
package main

import (
    _ "github.com/k2io/go-k2secure"  // import K2 package
    "fmt"
    "net/http"
)

func main() {
    http.HandleFunc("/", HelloServer)
    http.ListenAndServe(":8080", nil)
}

func HelloServer(w http.ResponseWriter, r *http.Request) {
    fmt.Fprintf(w, "Hello, %s!", r.URL.Path[1:])
}
```
    
## License

