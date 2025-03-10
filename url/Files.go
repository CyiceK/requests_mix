package url

import (
	"bytes"
	"fmt"
	"io"
	"mime/multipart"
	"net/textproto"
	"os"
	"strings"
	"sync"
)

// 初始化Files结构体
func NewFiles() *Files {
	return &Files{
		mutex: &sync.RWMutex{},
	}
}

// Files结构体
type Files struct {
	files    []map[string][]map[string]string
	indexKey []string
	mutex    *sync.RWMutex
}

// Files设置Field参数
func (fs *Files) SetField(name, value string) {
	fs.setParam(name, map[string]string{
		"type":  "field",
		"value": value,
	})
}

// Files设置File参数
func (fs *Files) SetFile(name, fileName, filePath, contentType string) {
	if contentType == "" {
		contentType = "application/octet-stream"
	}
	fs.setParam(name, map[string]string{
		"type":        "file",
		"value":       fileName,
		"path":        filePath,
		"contentType": contentType,
	})
}

// 设置参数的通用方法
func (fs *Files) setParam(name string, param map[string]string) {
	fs.mutex.Lock()
	defer fs.mutex.Unlock()
	f := map[string][]map[string]string{
		name: {param},
	}
	index := SearchStrings(fs.indexKey, name)
	if len(fs.indexKey) == 0 || index == -1 {
		fs.files = append(fs.files, f)
		fs.indexKey = append(fs.indexKey, name)
	} else {
		fs.files[index] = f
	}
}

// 获取Files参数值
func (fs *Files) Get(name string) map[string]string {
	fs.mutex.RLock()
	defer fs.mutex.RUnlock()
	if len(fs.files) != 0 {
		index := SearchStrings(fs.indexKey, name)
		if index != -1 {
			return fs.files[index][name][0]
		}
	}
	return nil
}

// Files添加Field参数
func (fs *Files) AddField(name, value string) {
	fs.addParam(name, map[string]string{
		"type":  "field",
		"value": value,
	})
}

// Files添加File参数
func (fs *Files) AddFile(name, fileName, filePath, contentType string) {
	if contentType == "" {
		contentType = "application/octet-stream"
	}
	fs.addParam(name, map[string]string{
		"type":        "file",
		"value":       fileName,
		"path":        filePath,
		"contentType": contentType,
	})
}

// 添加参数的通用方法
func (fs *Files) addParam(name string, param map[string]string) {
	fs.mutex.Lock()
	defer fs.mutex.Unlock()
	index := SearchStrings(fs.indexKey, name)
	if len(fs.indexKey) == 0 || index == -1 {
		fs.setParam(name, param)
	} else {
		fs.files[index][name] = append(fs.files[index][name], param)
	}
}

// 删除Files参数
func (fs *Files) Del(name string) bool {
	fs.mutex.Lock()
	defer fs.mutex.Unlock()
	index := SearchStrings(fs.indexKey, name)
	if len(fs.indexKey) == 0 || index == -1 {
		return false
	}
	fs.files = append(fs.files[:index], fs.files[index+1:]...)
	fs.indexKey = append(fs.indexKey[:index], fs.indexKey[index+1:]...)
	return true
}

// Files结构体转FormFile
func (fs *Files) Encode() (*bytes.Buffer, string, error) {
	fs.mutex.RLock()
	defer fs.mutex.RUnlock()
	body := &bytes.Buffer{}
	writer := multipart.NewWriter(body)

	for index, name := range fs.indexKey {
		itemList := fs.files[index][name]
		for _, item := range itemList {
			if item["type"] == "field" {
				writer.WriteField(name, item["value"])
			} else {
				if err := fs.writeFile(writer, name, item); err != nil {
					return nil, "", err
				}
			}
		}
	}
	if err := writer.Close(); err != nil {
		return nil, "", err
	}
	return body, writer.FormDataContentType(), nil
}

// 写入文件
func (fs *Files) writeFile(writer *multipart.Writer, name string, item map[string]string) error {
	contentType := item["contentType"]
	if contentType == "" {
		contentType = "application/octet-stream"
	}
	h := fs.createFormFileHeader(name, item["value"], contentType)
	uploadWriter, err := writer.CreatePart(h)
	if err != nil {
		return err
	}
	uploadFile, err := os.Open(item["path"])
	if err != nil {
		return err
	}
	defer uploadFile.Close()
	if _, err = io.Copy(uploadWriter, uploadFile); err != nil {
		return err
	}
	return nil
}

// 创建文件Header
func (fs *Files) createFormFileHeader(name, fileName, contentType string) textproto.MIMEHeader {
	h := make(textproto.MIMEHeader)
	h.Set("Content-Disposition", fmt.Sprintf(`form-data; name="%s"; filename="%s"`,
		strings.NewReplacer("\\", "\\\\", `"`, "\\\"").Replace(name),
		strings.NewReplacer("\\", "\\\\", `"`, "\\\"").Replace(fileName)))
	h.Set("Content-Type", contentType)
	return h
}
