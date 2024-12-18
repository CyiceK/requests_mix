package main

import (
	"fmt"
	"github.com/CyiceK/requests_mix"
	"github.com/CyiceK/requests_mix/url"
)

func main() {
	req := url.NewRequest()
	headers := url.NewHeaders()
	headers.Set("User-Agent", "123")
	req.Headers = headers
	req.Body = "testdata"
	r, _ := requests.Post("https://httpbin.org/post", req)
	fmt.Println(r.Text)
}
