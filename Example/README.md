# Example
## hello
### Source Code
```
package main

import "fmt"

func main() {
    fmt.Println("hello")
}

```

go build command: `go build -o hello.exe hello.go`

### Files
- IDA Generated: 0, hello.c
- Generator: hello.asm
- Sniffer: report.txt
- Analyzer
    - all_function.txt
    - missing_functions.txt
    - organized_code.txt
    - flow_chart.txt
- Extractor
    - ir.txt
    - ir_with_idainfo.txt
    - ir_summary.txt