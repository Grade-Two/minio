package cst

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha1"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	"mime/multipart"
	"net/http"
	"net/textproto"
	"strconv"
	"strings"
	"time"

	"github.com/minio/minio/pkg/hash"
)

type jsonBodyStruct struct {
	PathOfURL string `json:"path_of_url"`
	Method    string `json:"method"`
	Deadline  int64  `json:"deadline"`
}

// AuthKey 访问密钥结构体
type AuthKey struct {
	AccessKey, SecretKey string
}

// Key 生成访问密钥
// param uri: 未编码的原始全路径（path?query）字符串
// param method: 请求方法 GET POST PUT PATCH等
// param timedelta: 安全凭证的有效期时间增量（基于当前时间戳），单位为秒s
func (ak AuthKey) Key(uri string, method string, timedelta int64) string {
	deadline := time.Now().Unix() + timedelta //获取时间戳
	body := jsonBodyStruct{PathOfURL: uri, Method: method, Deadline: deadline}
	data, _ := json.Marshal(body)
	dataBase64 := base64.URLEncoding.EncodeToString(data)
	h := hmac.New(sha1.New, []byte(ak.SecretKey))
	h.Write([]byte(dataBase64))
	key := base64.URLEncoding.EncodeToString(h.Sum(nil))
	return fmt.Sprintf("%s %s:%s:%s", "evhb-auth", ak.AccessKey, key, dataBase64)
}

func buildAuthorization(client CSTClient, url string, mothed string, timedelta int64) string {
	if client.usekey == true {
		key := AuthKey{client.accesskey, client.secretkey}
		return key.Key(url, mothed, timedelta)
	}
	return client.authorization
}

func jsonToMap(jresult string) map[string]interface{} {
	var result map[string]interface{}
	json.Unmarshal([]byte(jresult), &result)
	return result
}

func _MyRequest(url string, mothed string, data io.Reader, contentType string, authorization string) (string, error) {
	request, _ := http.NewRequest(mothed, url, data)
	request.Header.Set("Content-Type", contentType)
	request.Header.Set("Authorization", authorization)
	response, err := (&http.Client{}).Do(request)
	if err != nil {
		fmt.Println(err)
		return "", err
	}
	defer response.Body.Close()
	body, _ := ioutil.ReadAll(response.Body)
	return string(body), nil
}

func _MakeBucketWithLocation(bucket string, client CSTClient) (map[string]interface{}, error) {
	url := "/" + client.version + "buckets/"
	mothed := "POST"
	contentType := "application/json"
	key := "Authorization: " + buildAuthorization(client, url, mothed, 30)
	data := make(map[string]interface{})
	data["name"] = bucket
	bytesData, _ := json.Marshal(data)
	result, _ := _MyRequest(client.baseURL+url, mothed, bytes.NewReader(bytesData), contentType, key)
	cstResult := jsonToMap(result)
	if cstResult["code"].(int) != 201 {
		if cstResult["code"].(int) == 400 && cstResult["existing"] == "true" {
			return cstResult, errors.New("BucketAlreadyExists")
		}
		if cstResult["code"].(int) == 400 {
			return cstResult, errors.New("ParameterError")
		}
		return cstResult, errors.New("OtherError")
	}
	return cstResult, nil
}

func _BucketInfo(bucket string, client CSTClient) (map[string]interface{}, error) {
	url := "/" + client.version + "buckets/" + bucket + "/?by-name=true"
	mothed := "GET"
	contentType := "application/json"
	key := "Authorization: " + buildAuthorization(client, url, mothed, 30)
	result, _ := _MyRequest(client.baseURL+url, mothed, nil, contentType, key)
	cstResult := jsonToMap(result)
	if cstResult["code"].(int) != 200 {
		if cstResult["code"].(int) == 400 {
			return cstResult, errors.New("NoSuchBucket")
		}
		return cstResult, errors.New("OtherError")
	}
	return cstResult, nil
}

func _ListBuckets(client CSTClient) ([]map[string]interface{}, error) {
	url := "/" + client.version + "buckets/"
	mothed := "GET"
	contentType := "application/json"
	key := "Authorization: " + buildAuthorization(client, url, mothed, 30)
	result, _ := _MyRequest(client.baseURL+url, mothed, nil, contentType, key)
	cstResult := jsonToMap(result)
	count := int(cstResult["count"].(float64))
	trueResult := make([]map[string]interface{}, count)
	for index := 0; index < count; index++ {
		re := make(map[string]interface{})
		re["name"] = cstResult["buckets"].([]interface{})[0].(map[string]interface{})["name"].(string)
		re["created_time"] = cstResult["buckets"].([]interface{})[0].(map[string]interface{})["created_time"].(string)
		trueResult[index] = re
	}
	return trueResult, nil
}

func _RemoveBuckets(bucket string, client CSTClient) (map[string]interface{}, error) {
	url := "/" + client.version + "buckets/" + bucket + "/?by-name=true"
	mothed := "DELETE"
	contentType := "application/json"
	key := "Authorization: " + buildAuthorization(client, url, mothed, 30)
	result, _ := _MyRequest(client.baseURL+url, mothed, nil, contentType, key)
	cstResult := jsonToMap(result)
	if cstResult["code"].(int) != 204 {
		if cstResult["code"].(int) == 404 {
			return cstResult, errors.New("NoSuchBucket")
		}
		return cstResult, errors.New("OtherError")
	}
	return cstResult, nil
}

func _ListObjects(bucket string, prefix string, client CSTClient) ([]map[string]interface{}, error) {
	url := "/" + client.version + "dir/" + bucket + "/"
	prefix = strings.Trim(prefix, "/")
	if len(prefix) > 0 {
		url += prefix + "/"
	}
	mothed := "GET"
	contentType := "application/json"
	key := "Authorization: " + buildAuthorization(client, url, mothed, 30)
	result, _ := _MyRequest(client.baseURL+url, mothed, nil, contentType, key)
	cstResult := jsonToMap(result)
	if cstResult["code"].(int) != 200 {
		if cstResult["code"].(int) == 404 && len(prefix) == 0 {
			return nil, errors.New("NoSuchBucket")
		}
		if cstResult["code"].(int) == 404 {
			return nil, errors.New("NoSuchPath")
		}
		return nil, errors.New("OtherError")
	}
	count := int(cstResult["count"].(float64))
	trueResult := make([]map[string]interface{}, count)
	for index := 0; index < count; index++ {
		re := make(map[string]interface{})
		m := cstResult["files"].([]interface{})[index].(map[string]interface{})
		re["bucket"] = cstResult["bucket_name"].(string)
		re["path"] = cstResult["dir_path"].(string)
		re["name"] = m["name"].(string)
		re["modTime"] = m["ult"].(string)
		re["isDir"] = m["fod"].(string)
		re["size"] = m["si"].(string)
		trueResult[index] = re
	}
	return trueResult, nil
}

func _ReadObject(bucket string, path string, offset int64, length int64, client CSTClient) (io.Reader, error) {
	url := ""
	path = strings.Trim(path, "/")
	mothed := "GET"
	contentType := "application/octet-stream"
	if length < 0 {
		length, _ = strconv.ParseInt("107374182400", 10, 64)
	}
	if offset == -1 {
		url = "/" + client.version + "obj/" + bucket + "/" + path + "/"
	} else {
		url = "/" + client.version + "obj/" + bucket + "/" + path + "/?offset=" +
			strconv.FormatInt(offset, 10) + "&size=" + strconv.FormatInt(length, 10)
	}
	key := "Authorization: " + buildAuthorization(client, url, mothed, 600)
	request, _ := http.NewRequest(client.baseURL+mothed, url, nil)
	request.Header.Set("Content-Type", contentType)
	request.Header.Set("Authorization", key)
	response, err := (&http.Client{}).Do(request)
	result, _ := ioutil.ReadAll(response.Body)
	if err != nil {
		fmt.Println(err)
		return nil, err
	}
	if len(response.Header.Get("evob_chunk_size")) == 0 {
		errResult := jsonToMap(string(result))
		if errResult["code"] == "404" {
			return nil, errors.New("ObjectNotFound")
		}
		return nil, errors.New("OtherError")
	}
	return response.Body, nil
}

/*
func _ReadObjectPart(url string, mothed string, authorization string) ([]byte, error) {
	request, _ := http.NewRequest(mothed, url, nil)
	request.Header.Set("Content-Type", "application/octet-stream")
	request.Header.Set("Authorization", authorization)
	response, err := (&http.Client{}).Do(request)
	result, _ := ioutil.ReadAll(response.Body)
	if err != nil {
		fmt.Println(err)
		return nil, err
	}
	// error
	if len(response.Header.Get("evob_chunk_size")) == 0 {
		errResult := jsonToMap(string(result))
		if errResult["code"] == "404" {
			return nil, errors.New("ObjectNotFound")
		}
		return nil, errors.New("OtherError")
	}
	return result, nil
}
*/

/*
func _ReadObject(bucket string, path string, offset int64, length int64, client CSTClient) ([]byte, error) {
	// download file part by part, each part's length set to 1B~4MB
	gap := int64(4 * 1024 * 1024)
	start_pos := offset / gap * gap
	end_pos := offset + length
	var result []byte
	path = strings.Trim(path, "/")
	mothed := "GET"
	for pos := start_pos; pos < end_pos; pos += gap {
		url := "/" + client.version + "obj/" + bucket + "/" + path + "/?offset=" +
			strconv.FormatInt(pos, 10) + "&size=" + strconv.FormatInt(gap, 10)
		key := "Authorization: " + buildAuthorization(client, url, mothed, 600)
		bs, err := _ReadObjectPart(client.baseURL+url, mothed, key)
		if err != nil {
			return result, err
		}
		if len(bs) == 0 {
			break
		}
		if pos == start_pos {
			result = bs
		} else {
			result = append(result, bs...)
		}
	}
	// remove left extra bytes
	if start_pos+int64(len(result)) <= offset {
		return nil, nil
	} else {
		result = result[offset-start_pos:]
	}
	// remove right extra bytes
	if int64(len(result)) > length {
		result = result[:length]
	}
	return result, nil
}
*/

func _ObjectInfo(bucket string, object string, client CSTClient) (map[string]interface{}, error) {
	object = strings.Trim(object, "/")
	url := "/" + client.version + "metadata/" + bucket + "/" + object + "/"
	mothed := "GET"
	contentType := "application/json"
	key := "Authorization: " + buildAuthorization(client, url, mothed, 30)
	result, _ := _MyRequest(client.baseURL+url, mothed, nil, contentType, key)
	cstResult := jsonToMap(result)
	if cstResult["code"].(int) != 200 {
		if cstResult["code"].(int) == 404 {
			return nil, errors.New("ObjectNotFound")
		}
		return nil, errors.New("OtherError")
	}
	return cstResult, nil
}

func _CreateDir(bucket string, prefix string, client CSTClient) (map[string]interface{}, error) {
	prefix = strings.Trim(prefix, "/")
	mothed := "POST"
	contentType := "application/json"
	pres := strings.Split(prefix, "/")
	for index, path := range pres {
		if len(path) == 0 {
			continue
		}
		url := "/" + client.version + "dir/" + bucket + "/" + strings.Join(pres[:index+1], "/") + "/"
		key := "Authorization: " + buildAuthorization(client, url, mothed, 30)
		result, _ := _MyRequest(client.baseURL+url, mothed, nil, contentType, key)
		cstResult := jsonToMap(result)
		if cstResult["code"].(int) != 201 && cstResult["code"].(int) != 400 {
			if cstResult["code"].(int) == 500 {
				return nil, errors.New("ObjectNotFound")
			}
			return nil, errors.New("OtherError")
		}
	}
	return _ObjectInfo(bucket, prefix, client)
}

func _DeleteDir(bucket string, prefix string, client CSTClient) error {
	prefix = strings.Trim(prefix, "/")
	mothed := "DELETE"
	contentType := "application/json"
	pres := strings.Split(prefix, "/")
	for i := len(pres) - 1; i >= 0; i-- {
		if len(pres[i]) == 0 {
			continue
		}
		url := "/" + client.version + "dir/" + bucket + "/" + strings.Join(pres[:i+1], "/") + "/"
		key := "Authorization: " + buildAuthorization(client, url, mothed, 30)
		result, _ := _MyRequest(client.baseURL+url, mothed, nil, contentType, key)
		cstResult := jsonToMap(result)
		if cstResult["code"].(int) != 204 {
			if cstResult["code"].(int) == 404 {
				return errors.New("ObjectNotFound")
			}
			if cstResult["code"].(int) == 400 {
				return nil
			}
			return errors.New("OtherError")
		}
	}
	return nil
}

func _PutChunk(url string, mothed string, data io.Reader, contentType string, authorization string) error {
	request, _ := http.NewRequest(mothed, url, data)
	request.Header.Set("Content-Type", contentType)
	request.Header.Set("Authorization", authorization)
	_, err := (&http.Client{}).Do(request)
	if err != nil {
		fmt.Println(err)
		return err
	}
	return nil
}

func _PutObject(bucket string, object string, data hash.Reader, size int64, client CSTClient) error {
	object = strings.Trim(object, "/")
	index := strings.LastIndexAny(object, "/")
	if index > 0 {
		_, err := _CreateDir(bucket, object[:index], client)
		if err != nil {
			return err
		}
	}
	mothed := "POST"
	url := "/" + client.version + "obj/" + bucket + "/" + object + "/"
	key := "Authorization: " + buildAuthorization(client, url, mothed, 600)
	// max byte length upload once
	maxChunkSize := int64(4 * 1024 * 1024)
	for offset := int64(0); offset < size; offset += maxChunkSize {
		// read next chunk
		var chunkSize int64
		if size-offset < maxChunkSize {
			chunkSize = size - offset
		} else {
			chunkSize = maxChunkSize
		}
		chunk := make([]byte, chunkSize)
		trueSize, err := data.Read(chunk)
		if err != nil && err != io.EOF {
			_DeleteObject(bucket, object, client)
			_DeleteDir(bucket, object[:index], client)
			return err
		}
		if int64(trueSize) != chunkSize {
			_DeleteObject(bucket, object, client)
			_DeleteDir(bucket, object[:index], client)
			return errors.New("UploadFail")
		}
		// fill post request
		bodyBuf := &bytes.Buffer{}
		bodyWriter := multipart.NewWriter(bodyBuf)
		var writer io.Writer
		h := make(textproto.MIMEHeader)
		h.Set("Content-Disposition", fmt.Sprintf(`form-data; name="%s"; filename="xxx"`, "chunk"))
		h.Set("Content-Type", "application/octet-stream")
		writer, err = bodyWriter.CreatePart(h)
		if err != nil {
			fmt.Println("error create writer")
			return err
		}
		closer := ioutil.NopCloser(bytes.NewReader(chunk))
		_, err = io.Copy(writer, closer)
		if err != nil {
			fmt.Println("error copy data")
			return err
		}
		closer.Close()
		params := map[string]string{
			"chunk_size":   strconv.Itoa(int(chunkSize)),
			"chunk_offset": strconv.FormatInt(offset, 10),
		}
		fmt.Println(params)
		for key, val := range params {
			_ = bodyWriter.WriteField(key, val)
		}
		// do
		_, err = _MyRequest(client.baseURL+url, mothed, bodyBuf, bodyWriter.FormDataContentType(), key)
		if err != nil {
			_DeleteObject(bucket, object, client)
			_DeleteDir(bucket, object[:index], client)
			return err
		}
	}
	return nil
}

func _PutObjectV2(bucket string, object string, data io.Reader, client CSTClient) error {
	object = strings.Trim(object, "/")
	index := strings.LastIndexAny(object, "/")
	if index > 0 {
		_, err := _CreateDir(bucket, object[:index], client)
		if err != nil {
			return err
		}
	}
	mothed := "POST"
	url := "/" + client.version + "obj/" + bucket + "/" + object + "/"
	key := "Authorization: " + buildAuthorization(client, url, mothed, 600)
	// max byte length upload once
	maxChunkSize := int64(4 * 1024 * 1024)
	conti := true
	for offset := int64(0); conti; offset += maxChunkSize {
		// read next chunk
		chunkSize := maxChunkSize
		chunk := make([]byte, chunkSize)
		trueSize, err := data.Read(chunk)
		if err != nil && err != io.EOF {
			_DeleteObject(bucket, object, client)
			_DeleteDir(bucket, object[:index], client)
			return err
		}
		if err == io.EOF || int64(trueSize) != chunkSize {
			chunkSize = int64(trueSize)
			conti = false
		}
		// fill post request
		bodyBuf := &bytes.Buffer{}
		bodyWriter := multipart.NewWriter(bodyBuf)
		var writer io.Writer
		h := make(textproto.MIMEHeader)
		h.Set("Content-Disposition", fmt.Sprintf(`form-data; name="%s"; filename="xxx"`, "chunk"))
		h.Set("Content-Type", "application/octet-stream")
		writer, err = bodyWriter.CreatePart(h)
		if err != nil {
			fmt.Println("error create writer")
			return err
		}
		closer := ioutil.NopCloser(bytes.NewReader(chunk))
		_, err = io.Copy(writer, closer)
		if err != nil {
			fmt.Println("error copy data")
			return err
		}
		closer.Close()
		params := map[string]string{
			"chunk_size":   strconv.Itoa(int(chunkSize)),
			"chunk_offset": strconv.FormatInt(offset, 10),
		}
		fmt.Println(params)
		for key, val := range params {
			_ = bodyWriter.WriteField(key, val)
		}
		// do
		_, err = _MyRequest(client.baseURL+url, mothed, bodyBuf, bodyWriter.FormDataContentType(), key)
		if err != nil {
			_DeleteObject(bucket, object, client)
			_DeleteDir(bucket, object[:index], client)
			return err
		}
	}
	return nil
}

func _DeleteObject(bucket string, object string, client CSTClient) error {
	object = strings.Trim(object, "/")
	mothed := "DELETE"
	contentType := "application/json"
	url := "/" + client.version + "dir/" + bucket + "/" + object + "/"
	key := "Authorization: " + buildAuthorization(client, url, mothed, 30)
	result, _ := _MyRequest(client.baseURL+url, mothed, nil, contentType, key)
	cstResult := jsonToMap(result)
	if cstResult["code"].(int) != 204 {
		if cstResult["code"].(int) == 404 {
			return errors.New("ObjectNotFound")
		}
		return errors.New("OtherError")
	}
	return _DeleteDir(bucket, object, client)
}

func _CopyObject(srcBucket string, dstBucket string, srcObject string, dstObject string, client CSTClient) error {
	data, err := _ReadObject(srcBucket, srcObject, -1, -1, client)
	if err != nil {
		return err
	}
	err = _PutObjectV2(dstBucket, dstObject, data, client)
	return err
}

func _SetDirPolicy(bucket string, object string, policy int, client CSTClient) error {
	if policy < 0 || policy > 2 {
		return errors.New("OtherError")
	}
	object = strings.Trim(object, "/")
	url := "/" + client.version + "dir/" + bucket + "/"
	if len(object) > 0 {
		url += object + "/"
	}
	url += "?share=" + strconv.Itoa(policy)
	mothed := "PATCH"
	contentType := "application/json"
	key := "Authorization: " + buildAuthorization(client, url, mothed, 30)
	result, _ := _MyRequest(client.baseURL+url, mothed, nil, contentType, key)
	cstResult := jsonToMap(result)
	if cstResult["code"].(int) != 200 {
		if cstResult["code"].(int) == 404 {
			return errors.New("ObjectNotFound")
		}
		return errors.New("OtherError")
	}
	return nil
}

func _SetBucketPolicy(bucket string, policy int, client CSTClient) error {
	if policy < 1 || policy > 3 {
		return errors.New("OtherError")
	}
	url := "/" + client.version + "dir/" + bucket + "/?by-name=true&public=" + strconv.Itoa(policy)
	mothed := "PATCH"
	contentType := "application/json"
	key := "Authorization: " + buildAuthorization(client, url, mothed, 30)
	result, _ := _MyRequest(client.baseURL+url, mothed, nil, contentType, key)
	cstResult := jsonToMap(result)
	if cstResult["code"].(int) != 200 {
		if cstResult["code"].(int) == 404 {
			return errors.New("ObjectNotFound")
		}
		return errors.New("OtherError")
	}
	return nil
}
