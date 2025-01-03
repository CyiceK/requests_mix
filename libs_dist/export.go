package main

/*
#include <stdlib.h>
*/
import "C"
import (
	"encoding/json"
	"errors"
	"fmt"
	http "github.com/CyiceK/chttp-mix"
	"github.com/CyiceK/chttp-mix/cookiejar"
	"github.com/CyiceK/requests_mix"
	"github.com/CyiceK/requests_mix/libs"
	ja3 "github.com/CyiceK/requests_mix/transport"
	"github.com/CyiceK/requests_mix/url"
	"github.com/CyiceK/requests_mix/utils"
	"github.com/google/uuid"
	cmap "github.com/orcaman/concurrent-map/v2"
	url2 "net/url"
	"strings"
	"sync"
	"time"
	"unsafe"
)

var unsafePointers = cmap.New[*C.char]()

// var unsafePointersLock = sync.Mutex{}
var errorFormat = "{\"err\": \"%v\"}"

var sessionsPool = cmap.New[*sync.Pool]()
var sessionsPoolLock = sync.Mutex{}

func GetSession(req libs.RequestParams) *requests.Session {
	if sp, ok := sessionsPool.Get(req.Id); ok {
		s := sp.Get().(*requests.Session)
		sp.Put(s)
		return s
	}
	sessionsPoolLock.Lock()
	defer sessionsPoolLock.Unlock()
	if sp, ok := sessionsPool.Get(req.Id); ok {
		s := sp.Get().(*requests.Session)
		sp.Put(s)
		return s
	}
	sp := &sync.Pool{
		New: func() interface{} {
			s := requests.NewSession()
			s.Headers = url.NewHeaders()
			return s
		},
	}
	sessionsPool.Set(req.Id, sp)
	s := sp.Get().(*requests.Session)
	sp.Put(s)
	return s
}

//export request
func request(requestParamsChar *C.char) *C.char {
	requestParamsString := C.GoString(requestParamsChar)
	requestParams := libs.RequestParams{}
	err := json.Unmarshal([]byte(requestParamsString), &requestParams)
	if err != nil {
		return C.CString(fmt.Sprintf(errorFormat, "request->err := json.Unmarshal([]byte(requestParamsString), &requestParams) failed: "+err.Error()))
	}

	req, err := buildRequest(requestParams)
	if err != nil {
		return C.CString(fmt.Sprintf(errorFormat, "request->req, err := buildRequest(requestParams) failed: "+err.Error()))
	}

	response, err := GetSession(requestParams).Request(requestParams.Method, requestParams.Url, req)
	if err != nil && strings.Contains(err.Error(), "EOF") {
		// retry 3 times
		for i := 0; i < 3; i++ {
			time.Sleep(time.Millisecond * time.Duration(i) * 100)
			response, err = GetSession(requestParams).Request(requestParams.Method, requestParams.Url, req)
			if err == nil {
				break
			}
		}
	}
	if err != nil {
		return C.CString(fmt.Sprintf(errorFormat, "request->response, err := GetSession(requestParams.Id).Request(requestParams.Method, requestParams.Url, req) failed: "+err.Error()))
	}

	responseParams := make(map[string]interface{})
	responseParams["id"] = uuid.New().String()
	responseParams["url"] = response.Url
	responseParams["headers"] = response.Headers
	responseParams["cookies"] = response.Cookies
	responseParams["status_code"] = response.StatusCode
	responseParams["content"] = utils.Base64Encode(response.Text)

	responseParamsString, err := json.Marshal(responseParams)
	if err != nil {
		return C.CString(fmt.Sprintf(errorFormat, "request->responseParamsString, err := json.Marshal(responseParams) failed: "+err.Error()))
	}
	responseString := C.CString(string(responseParamsString))

	//unsafePointersLock.Lock()
	unsafePointers.Set(responseParams["id"].(string), responseString)
	//defer unsafePointersLock.Unlock()

	return responseString
}

func buildRequest(requestParams libs.RequestParams) (*url.Request, error) {
	if requestParams.Method == "" {
		return nil, errors.New("method is null")
	}

	if requestParams.Url == "" {
		return nil, errors.New("url is null")
	}

	req := url.NewRequest()
	if requestParams.Params != nil {
		params := url.NewParams()
		for key, value := range requestParams.Params {
			params.Set(key, value)
		}
		req.Params = params
	}

	req.Headers = url.NewHeaders()
	if requestParams.PseudoHeaderOrder != nil {
		(*req.Headers)[http.PHeaderOrderKey] = requestParams.PseudoHeaderOrder
	}
	if requestParams.Headers != nil {
		//headers := url.NewHeaders()
		for key, value := range requestParams.Headers {
			if strings.ToLower(key) != "content-length" {
				req.Headers.Set(key, value)
			}
		}
		//req.Headers = headers
		//if requestParams.HeadersOrder != nil {
		//	(*req.Headers)[http.HeaderOrderKey] = requestParams.HeadersOrder
		//}
		//if requestParams.UnChangedHeaderKey != nil {
		//	(*req.Headers)[http.UnChangedHeaderKey] = requestParams.UnChangedHeaderKey
		//}
	}
	if requestParams.HeadersOrder != nil {
		(*req.Headers)[http.HeaderOrderKey] = requestParams.HeadersOrder
	}
	if requestParams.UnChangedHeaderKey != nil {
		(*req.Headers)[http.UnChangedHeaderKey] = requestParams.UnChangedHeaderKey
	}

	if requestParams.Cookies != nil {
		cookies, _ := cookiejar.New(nil)
		u, _ := url2.Parse(requestParams.Url)
		for key, value := range requestParams.Cookies {
			cookies.SetCookies(u, []*http.Cookie{&http.Cookie{
				Name:  key,
				Value: value,
			}})
		}
		req.Cookies = cookies
	}

	if requestParams.Data != nil {
		data := url.NewData()
		for key, value := range requestParams.Data {
			data.Set(key, value)
		}
		req.Data = data
	}

	if requestParams.Json != nil {
		req.Json = requestParams.Json
	}

	if requestParams.Body != "" {
		req.Body = requestParams.Body
	}

	if requestParams.Auth != nil {
		req.Auth = requestParams.Auth
	}

	if requestParams.Timeout != 0 {
		timeout := requestParams.Timeout
		req.Timeout = time.Duration(timeout) * time.Second
	}

	req.AllowRedirects = requestParams.AllowRedirects

	if requestParams.Proxies != "" {
		req.Proxies = requestParams.Proxies
	}

	req.Verify = requestParams.Verify

	if requestParams.Cert != nil {
		req.Cert = requestParams.Cert
	}

	if requestParams.Ja3 != "" {
		req.Ja3 = requestParams.Ja3
	}

	if requestParams.ForceHTTP1 {
		req.ForceHTTP1 = requestParams.ForceHTTP1
	}

	//if requestParams.PseudoHeaderOrder != nil {
	//	(*req.Headers)[http.PHeaderOrderKey] = requestParams.PseudoHeaderOrder
	//}

	if requestParams.TLSExtensions != "" {
		tlsExtensions := &ja3.Extensions{}
		err := json.Unmarshal([]byte(requestParams.TLSExtensions), tlsExtensions)
		if err != nil {
			return nil, err
		}
		req.TLSExtensions = ja3.ToTLSExtensions(tlsExtensions)
	}

	if requestParams.HTTP2Settings != "" {
		http2Settings := &ja3.H2Settings{}
		err := json.Unmarshal([]byte(requestParams.HTTP2Settings), http2Settings)
		if err != nil {
			return nil, err
		}
		req.HTTP2Settings = ja3.ToHTTP2Settings(http2Settings)
	}
	return req, nil
}

//export freeMemory
func freeMemory(responseId *C.char) {
	responseIdString := C.GoString(responseId)

	//unsafePointersLock.Lock()
	//defer unsafePointersLock.Unlock()

	ptr, ok := unsafePointers.Get(responseIdString)

	if !ok {
		fmt.Println("freeMemory:", ok)
		return
	}

	if ptr != nil {
		defer C.free(unsafe.Pointer(ptr))
	}

	unsafePointers.Remove(responseIdString)
}

func main() {
	defer func() {
		if r := recover(); r != nil {
			// 处理 panic，可以记录日志或采取其他措施
			fmt.Println("Recovered from panic:", r)
		}
	}()
}
