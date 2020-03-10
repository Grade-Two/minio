package cst

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/minio/cli"
	miniogopolicy "github.com/minio/minio-go/v6/pkg/policy"
	"github.com/minio/minio-go/v6/pkg/s3utils"
	minio "github.com/minio/minio/cmd"
	"github.com/minio/minio/cmd/logger"
	"github.com/minio/minio/pkg/auth"
	"github.com/minio/minio/pkg/bucket/policy"
	"github.com/minio/minio/pkg/bucket/policy/condition"
	"github.com/minio/minio/pkg/hash"
)

const (
	cstBackend = "cst"
	// PolicyDirPrivate represents private policy for dir.
	PolicyDirPrivate = 0
	// PolicyDirPublic represents public readonly policy for dir.
	PolicyDirPublic = 1
	// PolicyDirPublicReadWrite represents public read and write policy for dir.
	PolicyDirPublicReadWrite = 2
	// PolicyBucketPublic represents public policy for bucket.
	PolicyBucketPublic = 1
	// PolicyBucketPrivate represents private policy for bucket.
	PolicyBucketPrivate = 2
	// PolicyBucketPublicReadWrite represents public read and write policy for bucket.
	PolicyBucketPublicReadWrite = 3
)

func init() {
	const cstGatewayTemplate = `NAME:
  {{.HelpName}} - {{.Usage}}

USAGE:
  {{.HelpName}} {{if .VisibleFlags}}[FLAGS]{{end}} [ENDPOINT]
{{if .VisibleFlags}}
FLAGS:
  {{range .VisibleFlags}}{{.}}
  {{end}}{{end}}
ENDPOINT:
  oss server endpoint. Default ENDPOINT is http://obs.cstcloud.cn/

EXAMPLES:
  1. Start minio gateway server for CST backend
     {{.Prompt}} {{.EnvVarSetCommand}} MINIO_ACCESS_KEY{{.AssignmentOperator}}accesskey
     {{.Prompt}} {{.EnvVarSetCommand}} MINIO_SECRET_KEY{{.AssignmentOperator}}secretkey
     {{.Prompt}} {{.HelpName}}

  2. Start minio gateway server for CST backend with edge caching enabled
     {{.Prompt}} {{.EnvVarSetCommand}} MINIO_ACCESS_KEY{{.AssignmentOperator}}accesskey
     {{.Prompt}} {{.EnvVarSetCommand}} MINIO_SECRET_KEY{{.AssignmentOperator}}secretkey
     {{.Prompt}} {{.EnvVarSetCommand}} MINIO_CACHE_DRIVES{{.AssignmentOperator}}"/mnt/drive1,/mnt/drive2,/mnt/drive3,/mnt/drive4"
     {{.Prompt}} {{.EnvVarSetCommand}} MINIO_CACHE_EXCLUDE{{.AssignmentOperator}}"bucket1/*,*.png"
     {{.Prompt}} {{.EnvVarSetCommand}} MINIO_CACHE_AFTER{{.AssignmentOperator}}3
     {{.Prompt}} {{.EnvVarSetCommand}} MINIO_CACHE_WATERMARK_LOW{{.AssignmentOperator}}75
     {{.Prompt}} {{.EnvVarSetCommand}} MINIO_CACHE_WATERMARK_HIGH{{.AssignmentOperator}}85
     {{.Prompt}} {{.EnvVarSetCommand}} MINIO_CACHE_QUOTA{{.AssignmentOperator}}90
     {{.Prompt}} {{.HelpName}}
`

	minio.RegisterGatewayCommand(cli.Command{
		Name:               "cst",
		Usage:              "CST Cloud",
		Action:             cstGatewayMain,
		CustomHelpTemplate: cstGatewayTemplate,
		HideHelpCommand:    true,
	})
}

// Handler for 'minio gateway cst' command line.
func cstGatewayMain(ctx *cli.Context) {
	if ctx.Args().First() == "help" {
		cli.ShowCommandHelpAndExit(ctx, cstBackend, 1)
	}
	URL := ctx.Args().First()
	logger.FatalIf(minio.ValidateGatewayArguments(ctx.GlobalString("address"), URL), "Invalid argument")
	minio.StartGateway(ctx, &CST{URL})
}

// CST implements Gateway.
type CST struct {
	baseURL string
}

// Name implements Gateway interface.
func (g *CST) Name() string {
	return cstBackend
}

// CSTClient implements cst client
type CSTClient struct {
	accesskey     string
	secretkey     string
	authorization string
	usekey        bool
	version       string
	baseURL       string
}

// cstObjects implements gateway for Aliyun Object Storage Service.
type cstObjects struct {
	minio.GatewayUnsupported
	client *CSTClient
}

// NewGatewayLayer implements Gateway interface and returns OSS ObjectLayer.
func (g *CST) NewGatewayLayer(creds auth.Credentials) (minio.ObjectLayer, error) {
	// Regions and endpoints
	if g.baseURL == "" {
		g.baseURL = "http://obs.cstcloud.cn"
	}

	// Initialize cst client struct.
	client := CSTClient{
		accesskey: creds.AccessKey,
		secretkey: creds.SecretKey,
		version:   "api/v1/",
		usekey:    true,
		baseURL:   g.baseURL,
	}

	return &cstObjects{
		client: &client,
	}, nil
}

// Production - hdfs gateway is production ready.
func (g *CST) Production() bool {
	return true
}

func cstToObjectError(err error, params ...string) error {
	if err == nil {
		return nil
	}
	bucket := ""
	object := ""
	uploadID := ""
	switch len(params) {
	case 3:
		uploadID = params[2]
		fmt.Println(uploadID)
		fallthrough
	case 2:
		object = params[1]
		fallthrough
	case 1:
		bucket = params[0]
	}

	switch err.Error() {
	case "BucketNotFound":
		return minio.BucketNotFound{Bucket: bucket}
	case "ObjectNotFound":
		return minio.ObjectNotFound{Bucket: bucket, Object: object}
	case "BucketAlreadyExists":
		return minio.BucketAlreadyOwnedByYou{Bucket: bucket}
	default:
		return err
	}
}

// Shutdown saves any gateway metadata to disk
// if necessary and reload upon next restart.
func (l *cstObjects) Shutdown(ctx context.Context) error {
	return nil
}

// StorageInfo is not relevant to CST backend.
func (l *cstObjects) StorageInfo(ctx context.Context, _ bool) minio.StorageInfo {
	sinfo := minio.StorageInfo{}
	sinfo.Backend.Type = minio.BackendGateway
	sinfo.Backend.GatewayOnline = true
	return sinfo
}

// cstIsValidBucketName verifies whether a bucket name is valid.
func cstIsValidBucketName(bucket string) bool {
	// dot is not allowed in bucket name
	if strings.Contains(bucket, ".") {
		return false
	}
	if s3utils.CheckValidBucketNameStrict(bucket) != nil {
		return false
	}
	return true
}

// MakeBucketWithLocation creates a new container on OSS backend.
func (l *cstObjects) MakeBucketWithLocation(ctx context.Context, bucket, location string) error {
	if !cstIsValidBucketName(bucket) {
		return minio.BucketNameInvalid{Bucket: bucket}
	}

	_, err := _MakeBucketWithLocation(bucket, *l.client)
	return cstToObjectError(err, bucket)
}

// cstGeBucketInfo gets bucket metadata.
func ossGeBucketInfo(ctx context.Context, client *CSTClient, bucket string) (bi minio.BucketInfo, err error) {
	bgir, err := _BucketInfo(bucket, *client)
	if err != nil {
		return bi, cstToObjectError(err, bucket)
	}

	t, _ := time.ParseInLocation("2006-01-02 15:04:05", bgir["created_time"].(string), time.Local)
	return minio.BucketInfo{
		Name:    bgir["name"].(string),
		Created: t,
	}, nil
}

// GetBucketInfo gets bucket metadata.
func (l *cstObjects) GetBucketInfo(ctx context.Context, bucket string) (bi minio.BucketInfo, err error) {
	return ossGeBucketInfo(ctx, l.client, bucket)
}

// ListBuckets lists all OSS buckets.
func (l *cstObjects) ListBuckets(ctx context.Context) (buckets []minio.BucketInfo, err error) {
	listInfo, err := _ListBuckets(*l.client)
	if err != nil {
		return nil, err
	}
	buckets = make([]minio.BucketInfo, len(listInfo))
	for index := 0; index < len(listInfo); index++ {
		t, _ := time.ParseInLocation("2006-01-02 15:04:05", listInfo[index]["created_time"].(string), time.Local)
		buckets[index] = minio.BucketInfo{
			Name:    listInfo[index]["name"].(string),
			Created: t,
		}
	}
	return buckets, nil
}

// DeleteBucket deletes a bucket on OSS.
func (l *cstObjects) DeleteBucket(ctx context.Context, bucket string) error {
	_, err := _RemoveBuckets(bucket, *l.client)
	if err != nil {
		return cstToObjectError(err, bucket)
	}
	return nil
}

// ossListObjects lists all blobs in OSS bucket filtered by prefix.
func cstListObjects(ctx context.Context, client *CSTClient, bucket, prefix string) (loi minio.ListObjectsInfo, err error) {
	los, err := _ListObjects(bucket, prefix, *client)
	if err != nil {
		return loi, cstToObjectError(err, bucket)
	}
	objects := make([]minio.ObjectInfo, len(los))
	for index := 0; index < len(los); index++ {
		t, _ := time.ParseInLocation("2006-01-02 15:04:05", los[index]["modTime"].(string), time.Local)
		isDir := false
		if los[index]["isDir"].(string) == "true" {
			isDir = true
		}
		objects[index] = minio.ObjectInfo{
			Bucket:  los[index]["bucket"].(string),
			Name:    los[index]["name"].(string),
			ModTime: t,
			Size:    int64(los[index]["size"].(float64)),
			IsDir:   isDir,
		}
	}
	prefixes := make([]string, 1)
	prefixes[0] = prefix
	return minio.ListObjectsInfo{
		Objects:  objects,
		Prefixes: prefixes,
	}, nil
}

// ListObjects lists all blobs in OSS bucket filtered by prefix.
func (l *cstObjects) ListObjects(ctx context.Context, bucket, prefix, marker, delimiter string, maxKeys int) (loi minio.ListObjectsInfo, err error) {
	return cstListObjects(ctx, l.client, bucket, prefix)
}

// ListObjectsV2 lists all blobs in OSS bucket filtered by prefix
func (l *cstObjects) ListObjectsV2(ctx context.Context, bucket, prefix, continuationToken, delimiter string, maxKeys int,
	fetchOwner bool, startAfter string) (loi minio.ListObjectsV2Info, err error) {
	resultV1, err := cstListObjects(ctx, l.client, bucket, prefix)
	if err != nil {
		return loi, cstToObjectError(err, bucket)
	}
	return minio.ListObjectsV2Info{
		Objects:               resultV1.Objects,
		Prefixes:              resultV1.Prefixes,
		ContinuationToken:     continuationToken,
		NextContinuationToken: resultV1.NextMarker,
		IsTruncated:           resultV1.IsTruncated,
	}, nil
}

// cstGetObject reads an object on CST. Supports additional
// parameters like offset and length which are synonymous with
// HTTP Range requests.
//
// startOffset indicates the starting read location of the object.
// length indicates the total length of the object.
func cstGetObject(ctx context.Context, client *CSTClient, bucket, key string, startOffset, length int64, writer io.Writer, etag string) error {
	if length < 0 && length != -1 {
		return cstToObjectError(fmt.Errorf("Invalid argument"), bucket, key)
	}

	if length == -1 {
		// 100GB
		length, _ = strconv.ParseInt("107374182400", 10, 64)
	}

	object, err := _ReadObject(bucket, key, startOffset, length, *client)

	if err != nil {
		return cstToObjectError(err, bucket, key)
	}

	if _, err := io.Copy(writer, object); err != nil {
		return cstToObjectError(err, bucket, key)
	}
	return nil
}

// GetObject reads an object on OSS. Supports additional
// parameters like offset and length which are synonymous with
// HTTP Range requests.
//
// startOffset indicates the starting read location of the object.
// length indicates the total length of the object.
func (l *cstObjects) GetObject(ctx context.Context, bucket, key string, startOffset, length int64, writer io.Writer, etag string, opts minio.ObjectOptions) error {
	return cstGetObject(ctx, l.client, bucket, key, startOffset, length, writer, etag)
}

// GetObjectNInfo - returns object info and locked object ReadCloser
func (l *cstObjects) GetObjectNInfo(ctx context.Context, bucket, object string, rs *minio.HTTPRangeSpec, h http.Header, lockType minio.LockType, opts minio.ObjectOptions) (gr *minio.GetObjectReader, err error) {
	var objInfo minio.ObjectInfo
	objInfo, err = l.GetObjectInfo(ctx, bucket, object, opts)
	if err != nil {
		return nil, err
	}

	var startOffset, length int64
	startOffset, length, err = rs.GetOffsetLength(objInfo.Size)
	if err != nil {
		return nil, err
	}

	pr, pw := io.Pipe()
	go func() {
		err := l.GetObject(ctx, bucket, object, startOffset, length, pw, objInfo.ETag, opts)
		pw.CloseWithError(err)
	}()
	// Setup cleanup function to cause the above go-routine to
	// exit in case of partial read
	pipeCloser := func() { pr.Close() }
	return minio.NewGetObjectReaderFromReader(pr, objInfo, opts.CheckCopyPrecondFn, pipeCloser)
}

// ossGetObjectInfo reads object info and replies back ObjectInfo.
func cstGetObjectInfo(ctx context.Context, client *CSTClient, bucket, object string) (objInfo minio.ObjectInfo, err error) {
	info, err := _ObjectInfo(bucket, object, *client)
	if err != nil {
		return objInfo, err
	}
	objInfo.Bucket = info["bucket"].(string)
	objInfo.Name = info["obj"].(map[string]interface{})["na"].(string)
	at, _ := time.ParseInLocation("2006-01-02 15:04:05", info["obj"].(map[string]interface{})["upt"].(string), time.Local)
	objInfo.AccTime = at
	ut, _ := time.ParseInLocation("2006-01-02 15:04:05", info["obj"].(map[string]interface{})["ult"].(string), time.Local)
	objInfo.ModTime = ut
	objInfo.IsDir = !info["obj"].(map[string]interface{})["fod"].(bool)
	objInfo.Size = info["obj"].(map[string]interface{})["si"].(int64)
	objInfo.ContentType = "application/json"

	return objInfo, nil
}

// GetObjectInfo reads object info and replies back ObjectInfo.
func (l *cstObjects) GetObjectInfo(ctx context.Context, bucket, object string, opts minio.ObjectOptions) (objInfo minio.ObjectInfo, err error) {
	return cstGetObjectInfo(ctx, l.client, bucket, object)
}

// cstPutObject creates a new object with the incoming data.
func cstPutObject(ctx context.Context, client *CSTClient, bucket, object string, data *hash.Reader, metadata map[string]string) (objInfo minio.ObjectInfo, err error) {
	err = _PutObject(bucket, object, *data, data.Size(), *client)
	if err != nil {
		return objInfo, cstToObjectError(err, bucket, object)
	}
	return cstGetObjectInfo(ctx, client, bucket, object)
}

// PutObject creates a new object with the incoming data.
func (l *cstObjects) PutObject(ctx context.Context, bucket, object string, r *minio.PutObjReader, opts minio.ObjectOptions) (objInfo minio.ObjectInfo, err error) {
	data := r.Reader

	return cstPutObject(ctx, l.client, bucket, object, data, opts.UserDefined)
}

// CopyObject copies an object from source bucket to a destination bucket.
func (l *cstObjects) CopyObject(ctx context.Context, srcBucket, srcObject, dstBucket, dstObject string, srcInfo minio.ObjectInfo, srcOpts, dstOpts minio.ObjectOptions) (objInfo minio.ObjectInfo, err error) {
	err = _CopyObject(srcBucket, dstBucket, srcObject, dstObject, *l.client)
	if err != nil {
		return objInfo, cstToObjectError(err, srcBucket, srcObject)
	}
	return l.GetObjectInfo(ctx, dstBucket, dstObject, dstOpts)
}

// DeleteObject deletes a blob in bucket.
func (l *cstObjects) DeleteObject(ctx context.Context, bucket, object string) error {
	err := _DeleteObject(bucket, object, *l.client)
	if err != nil {
		logger.LogIf(ctx, err)
		return cstToObjectError(err, bucket, object)
	}
	return nil
}

func (l *cstObjects) DeleteObjects(ctx context.Context, bucket string, objects []string) ([]error, error) {
	errs := make([]error, len(objects))
	for idx, object := range objects {
		errs[idx] = l.DeleteObject(ctx, bucket, object)
	}
	return errs, nil
}

// ListMultipartUploads lists all multipart uploads.
func (l *cstObjects) ListMultipartUploads(ctx context.Context, bucket, prefix, keyMarker, uploadIDMarker, delimiter string, maxUploads int) (lmi minio.ListMultipartsInfo, err error) {
	// not support
	return lmi, nil
}

// NewMultipartUpload upload object in multiple parts.
func (l *cstObjects) NewMultipartUpload(ctx context.Context, bucket, object string, o minio.ObjectOptions) (uploadID string, err error) {
	// not support
	return "0", nil
}

// PutObjectPart puts a part of object in bucket.
func (l *cstObjects) PutObjectPart(ctx context.Context, bucket, object, uploadID string, partID int, r *minio.PutObjReader, opts minio.ObjectOptions) (pi minio.PartInfo, err error) {
	data := r.Reader
	err = _PutObject(bucket, object, *data, data.Size(), *l.client)

	return minio.PartInfo{
		Size: data.Size(),
	}, nil
}

func ossBuildListObjectPartsParams(uploadID string, partNumberMarker, maxParts int) map[string]interface{} {
	return map[string]interface{}{
		"uploadId":           uploadID,
		"part-number-marker": strconv.Itoa(partNumberMarker),
		"max-parts":          strconv.Itoa(maxParts),
	}
}

// CopyObjectPart creates a part in a multipart upload by copying
// existing object or a part of it.
func (l *cstObjects) CopyObjectPart(ctx context.Context, srcBucket, srcObject, destBucket, destObject, uploadID string,
	partID int, startOffset, length int64, srcInfo minio.ObjectInfo, srcOpts, dstOpts minio.ObjectOptions) (p minio.PartInfo, err error) {
	// not support
	return p, nil
}

// ListObjectParts returns all object parts for specified object in specified bucket
func (l *cstObjects) ListObjectParts(ctx context.Context, bucket, object, uploadID string, partNumberMarker, maxParts int, opts minio.ObjectOptions) (lpi minio.ListPartsInfo, err error) {
	// not support
	return lpi, nil
}

// AbortMultipartUpload aborts a ongoing multipart upload.
func (l *cstObjects) AbortMultipartUpload(ctx context.Context, bucket, object, uploadID string) error {
	// not support
	return nil
}

// CompleteMultipartUpload completes ongoing multipart upload and finalizes object.
func (l *cstObjects) CompleteMultipartUpload(ctx context.Context, bucket, object, uploadID string, uploadedParts []minio.CompletePart, opts minio.ObjectOptions) (oi minio.ObjectInfo, err error) {
	// not support
	return oi, nil
}

// SetBucketPolicy sets policy on bucket.
// CST supports three types of bucket policies:
// PolicyBucketPublicReadWrite: readwrite in minio terminology
// PolicyBucketPublic: readonly in minio terminology
// PolicyBucketPrivate: none in minio terminology
func (l *cstObjects) SetBucketPolicy(ctx context.Context, bucket string, bucketPolicy *policy.Policy) error {
	policyInfo, err := minio.PolicyToBucketAccessPolicy(bucketPolicy)
	if err != nil {
		// This should not happen.
		return cstToObjectError(err, bucket)
	}

	bucketPolicies := miniogopolicy.GetPolicies(policyInfo.Statements, bucket, "")
	if len(bucketPolicies) != 1 {
		return minio.NotImplemented{}
	}

	prefix := bucket + "/*" // For all objects inside the bucket.
	for policyPrefix, bucketPolicy := range bucketPolicies {
		if policyPrefix != prefix {
			logger.LogIf(ctx, minio.NotImplemented{})
			return minio.NotImplemented{}
		}

		var acl int
		switch bucketPolicy {
		case miniogopolicy.BucketPolicyNone:
			acl = PolicyBucketPrivate
		case miniogopolicy.BucketPolicyReadOnly:
			acl = PolicyBucketPublic
		case miniogopolicy.BucketPolicyReadWrite:
			acl = PolicyBucketPublicReadWrite
		default:
			return minio.NotImplemented{}
		}

		err := _SetBucketPolicy(bucket, acl, *l.client)
		if err != nil {
			return cstToObjectError(err, bucket)
		}
	}

	return nil
}

// GetBucketPolicy will get policy on bucket.
func (l *cstObjects) GetBucketPolicy(ctx context.Context, bucket string) (*policy.Policy, error) {
	info, err := _BucketInfo(bucket, *l.client)
	if err != nil {
		logger.LogIf(ctx, err)
		return nil, cstToObjectError(err)
	}
	var readOnly, readWrite bool
	switch info["access_permission"].(string) {
	case string("私有"):
		// By default, all buckets starts with a "private" policy.
		return nil, cstToObjectError(minio.BucketPolicyNotFound{}, bucket)
	case string("公有"):
		readOnly = true
	default:
		return nil, minio.NotImplemented{}
	}

	actionSet := policy.NewActionSet()
	if readOnly {
		actionSet.Add(policy.GetBucketLocationAction)
		actionSet.Add(policy.ListBucketAction)
		actionSet.Add(policy.GetObjectAction)
	}
	if readWrite {
		actionSet.Add(policy.GetBucketLocationAction)
		actionSet.Add(policy.ListBucketAction)
		actionSet.Add(policy.GetObjectAction)
		actionSet.Add(policy.ListBucketMultipartUploadsAction)
		actionSet.Add(policy.AbortMultipartUploadAction)
		actionSet.Add(policy.DeleteObjectAction)
		actionSet.Add(policy.ListMultipartUploadPartsAction)
		actionSet.Add(policy.PutObjectAction)
	}

	return &policy.Policy{
		Version: policy.DefaultVersion,
		Statements: []policy.Statement{
			policy.NewStatement(
				policy.Allow,
				policy.NewPrincipal("*"),
				actionSet,
				policy.NewResourceSet(
					policy.NewResource(bucket, ""),
					policy.NewResource(bucket, "*"),
				),
				condition.NewFunctions(),
			),
		},
	}, nil
}

// DeleteBucketPolicy deletes all policies on bucket.
func (l *cstObjects) DeleteBucketPolicy(ctx context.Context, bucket string) error {
	err := _SetBucketPolicy(bucket, PolicyBucketPrivate, *l.client)
	if err != nil {
		return cstToObjectError(err, bucket)
	}
	return nil
}

// IsCompressionSupported returns whether compression is applicable for this layer.
func (l *cstObjects) IsCompressionSupported() bool {
	return false
}

// IsReady returns whether the layer is ready to take requests.
func (l *cstObjects) IsReady(ctx context.Context) bool {
	return true
}
