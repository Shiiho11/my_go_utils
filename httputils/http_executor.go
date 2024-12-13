package httputils

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
)

const (
	CONTENT_TYPE                = "Content-Type"
	APPLICATION_JSON            = "application/json"
	APPLICATION_FORM_URLENCODED = "application/x-www-form-urlencoded"
)

// HTTP request executor.
//
// Example:
//
//	err := httputils.NewHttpExecutor(http.DefaultClient).
//		Url("https://rest.apipost.net/users/{username}").
//		Headers(map[string]string{"apikey": "your apikey"}).
//		Body(RequestData{}, httputils.APPLICATION_JSON).
//		Method(http.MethodGet).
//		Execute(&ResultData{}, httputils.APPLICATION_JSON).
//		Error
type HttpExecutor struct {
	client  *http.Client
	url     string
	method  string
	headers map[string]string
	body    io.Reader
	Error   error
}

func NewHttpExecutor(client *http.Client) *HttpExecutor {
	return &HttpExecutor{
		client:  client,
		method:  http.MethodGet,
		headers: make(map[string]string),
		body:    nil,
		Error:   nil,
	}
}

func (he *HttpExecutor) Url(url string) *HttpExecutor {
	he.url = url
	return he
}

func (he *HttpExecutor) Method(method string) *HttpExecutor {
	he.method = method
	return he
}

func (he *HttpExecutor) Headers(headers map[string]string) *HttpExecutor {
	he.headers = headers
	return he
}

// Set requset body.
//
// If contentType is specified, data will be encoded according to the specified contentType.
//
//	| data.(type)                 | contentType                         |
//	| --------------------------- | ----------------------------------- |
//	| string | []byte | io.Reader | nil                                 |
//	| any                         | "application/json"                  |
//	| map[string]string           | "application/x-www-form-urlencoded" |
func (he *HttpExecutor) Body(data any, contentType ...string) *HttpExecutor {
	if data == nil {
		return he
	}

	// if contentType is empty, there is no need to encoded the data
	if len(contentType) == 0 {
		// if contentType is empty, data: string | []byte | io.Reader
		switch data := data.(type) {
		case string:
			he.body = strings.NewReader(data)
		case []byte:
			he.body = bytes.NewReader(data)
		case io.Reader:
			he.body = data
		default:
			he.Error = fmt.Errorf("request body: unsupported data type: %T,"+
				" use contentType param to encode data", data)
		}
		return he
	}

	// encode data
	switch contentType[0] {
	case APPLICATION_JSON:
		body, err := json.Marshal(data)
		if err != nil {
			he.Error = err
			return he
		}
		he.body = bytes.NewReader(body)
		he.headers[CONTENT_TYPE] = APPLICATION_JSON
	case APPLICATION_FORM_URLENCODED:
		// check data type and convert to map[string]string
		data, ok := data.(map[string]string)
		if !ok {
			he.Error = fmt.Errorf("request body: Content-Type: %s, data type must be map[string]string, but got %T",
				APPLICATION_FORM_URLENCODED, data)
			return he
		}
		// encode data
		body := url.Values{}
		for k, v := range data {
			body.Add(k, v)
		}
		he.body = strings.NewReader(body.Encode())
		he.headers[CONTENT_TYPE] = APPLICATION_FORM_URLENCODED
	default:
		he.Error = fmt.Errorf("request body: unsupported Content-Type: %s", contentType[0])
	}
	return he
}

// Execute HTTP request.
//
// The data must be a pointer. Response body will be written to data.
//
// If contentType is specified, data will be decoded according to the specified contentType.
//
//	| data.(type)                 | contentType                         |
//	| --------------------------- | ----------------------------------- |
//	| *string | *[]byte           | nil                                 |
//	| any                         | "application/json"                  |
func (he *HttpExecutor) Execute(data any, contentType ...string) *HttpExecutor {
	// check error
	if he.Error != nil {
		return he
	}
	// create request
	req, err := http.NewRequest(he.method, he.url, he.body)
	if err != nil {
		he.Error = err
		return he
	}
	// add headers
	for k, v := range he.headers {
		req.Header.Add(k, v)
	}
	// execute request
	res, err := he.client.Do(req)
	if err != nil {
		he.Error = err
		return he
	}
	defer res.Body.Close()
	// read response
	resBody, err := io.ReadAll(res.Body)
	if err != nil {
		he.Error = err
		return he
	}

	// if contentType is empty, there is no need to decoded the data
	if len(contentType) == 0 {
		// if contentType is empty, data: *string | *[]byte
		switch data := data.(type) {
		case *string:
			*data = string(resBody)
		case *[]byte:
			*data = resBody
		default:
			he.Error = fmt.Errorf("response body: unsupported data type: %T"+
				" use contentType param to decode data", data)
		}
		return he
	}

	// decode data
	switch contentType[0] {
	case APPLICATION_JSON:
		err = json.Unmarshal(resBody, data)
		if err != nil {
			he.Error = err
			return he
		}
	default:
		he.Error = fmt.Errorf("response body: unsupported Content-Type: %s", contentType[0])
	}
	return he
}
